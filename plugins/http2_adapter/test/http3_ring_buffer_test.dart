import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

void main() {
  test('preserves FIN when a stream write ring saturates and wraps', () async {
    final harness = await _InspectorHarness.start(const [
      '--echo-application-data',
      '--initial-max-data',
      '1',
      '--initial-max-stream-data',
      '1',
    ]);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      final streamId = await _openBidirectionalStream(socket);

      final received = BytesBuilder(copy: false);
      final finished = Completer<void>();
      final peerStreams = <int>{};
      void drainReads() {
        _drainPeerStreams(socket!, peerStreams);
        while (true) {
          final chunk = socket.streamRead(streamId);
          if (chunk == null) return;
          if (chunk.isEmpty) {
            if (!finished.isCompleted) finished.complete();
            return;
          }
          received.add(chunk);
        }
      }

      subscription = socket.listen(
        (event) {
          if (event == RawSocketEvent.read) drainReads();
        },
        onError: finished.completeError,
      );

      final chunk = Uint8List.fromList(
        List<int>.generate(8192, (index) => (index * 17) & 0xff),
      );
      final expected = BytesBuilder(copy: false);
      var queued = 0;
      while (true) {
        final written = socket.streamWrite(streamId, chunk);
        if (written == 0) break;
        expected.add(Uint8List.sublistView(chunk, 0, written));
        queued += written;
      }
      expect(queued, greaterThan(8 * 1024));
      expect(queued, lessThan(16 * 1024));

      // FIN is sideband state and must remain pending while the stream ring is
      // full, then follow the final buffered byte.
      socket.streamClose(streamId);
      await _withInspectorDiagnostics(finished.future, harness);

      expect(received.takeBytes(), orderedEquals(expected.takeBytes()));
      await harness.waitForOutput(
        (line) =>
            line.contains('STREAM id=$streamId') && line.contains('fin=true'),
      );
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('backpressures concurrent streams through bounded packet queues',
      () async {
    final harness = await _InspectorHarness.start(const [
      '--echo-application-data',
      '--quiet',
    ]);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      // Twelve full stream rings exceed the bounded native application-packet
      // queue. Writes must resume as congestion and socket capacity return.
      const streamCount = 12;
      const bytesPerStream = 32 * 1024;
      final streamIds = <int>[];
      final expected = <int, Uint8List>{};
      final writeOffsets = <int, int>{};
      final received = <int, BytesBuilder>{};
      final finished = <int, Completer<void>>{};
      final closed = <int>{};
      final peerStreams = <int>{};
      for (var streamIndex = 0; streamIndex < streamCount; streamIndex++) {
        final streamId = await _openBidirectionalStream(socket);
        streamIds.add(streamId);
        expected[streamId] = Uint8List.fromList(List<int>.generate(
          bytesPerStream,
          (index) => (streamIndex * 53 + index * 29) & 0xff,
        ));
        writeOffsets[streamId] = 0;
        received[streamId] = BytesBuilder(copy: false);
        finished[streamId] = Completer<void>();
      }

      var allowReads = false;
      var pumpingWrites = false;
      void drainReads() {
        if (!allowReads) return;
        _drainPeerStreams(socket!, peerStreams);
        for (final streamId in streamIds) {
          while (true) {
            final chunk = socket.streamRead(streamId);
            if (chunk == null) break;
            if (chunk.isEmpty) {
              final completer = finished[streamId]!;
              if (!completer.isCompleted) completer.complete();
              break;
            }
            received[streamId]!.add(chunk);
          }
        }
      }

      void pumpWrites() {
        if (pumpingWrites) return;
        pumpingWrites = true;
        socket!.writeEventsEnabled = false;
        try {
          var madeProgress = true;
          while (madeProgress) {
            madeProgress = false;
            for (final streamId in streamIds) {
              final data = expected[streamId]!;
              final offset = writeOffsets[streamId]!;
              if (offset == data.length) {
                if (closed.add(streamId)) socket.streamClose(streamId);
                continue;
              }
              final written = socket.streamWrite(streamId, data, offset);
              if (written == 0) continue;
              writeOffsets[streamId] = offset + written;
              madeProgress = true;
              if (offset + written == data.length && closed.add(streamId)) {
                socket.streamClose(streamId);
              }
            }
          }
          if (closed.length != streamCount) {
            socket.writeEventsEnabled = true;
          }
        } finally {
          pumpingWrites = false;
        }
      }

      subscription = socket.listen(
        (event) {
          if (event == RawSocketEvent.write) pumpWrites();
          if (event == RawSocketEvent.read) drainReads();
        },
        onError: (Object error, StackTrace stackTrace) {
          for (final completer in finished.values) {
            if (!completer.isCompleted) {
              completer.completeError(error, stackTrace);
            }
          }
        },
      );

      pumpWrites();
      await _waitUntil(
        () => closed.length == streamCount,
        diagnostics: () => 'writeOffsets=$writeOffsets closed=$closed\n'
            '${harness.output.join('\n')}',
      );
      await Future<void>.delayed(const Duration(milliseconds: 75));
      allowReads = true;
      drainReads();
      await _withInspectorDiagnostics(
        Future.wait(finished.values.map((completer) => completer.future)),
        harness,
      );

      for (final streamId in streamIds) {
        expect(
          received[streamId]!.takeBytes(),
          orderedEquals(expected[streamId]!),
          reason: 'stream $streamId',
        );
      }
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('wraps unreliable DATAGRAM slots in both directions', () async {
    final harness =
        await _InspectorHarness.start(const ['--echo-application-data']);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      const datagramCount = 64;
      const datagramSize = 512;
      final expected = <int, Uint8List>{
        for (var index = 0; index < datagramCount; index++)
          index: Uint8List.fromList(List<int>.generate(
            datagramSize,
            (offset) => offset < 4
                ? (index >> ((3 - offset) * 8)) & 0xff
                : (index * 31 + offset * 7) & 0xff,
          )),
      };
      final received = <int, Uint8List>{};
      final finished = Completer<void>();
      final peerStreams = <int>{};
      var nextToSend = 0;
      var pumpingWrites = false;

      void drainReads() {
        _drainPeerStreams(socket!, peerStreams);
        while (true) {
          final payload = socket.receive();
          if (payload == null) break;
          if (payload.length != datagramSize) {
            finished.completeError(
              StateError('Unexpected DATAGRAM length ${payload.length}'),
            );
            return;
          }
          final index = (payload[0] << 24) |
              (payload[1] << 16) |
              (payload[2] << 8) |
              payload[3];
          received[index] = payload;
        }
        if (received.length == datagramCount && !finished.isCompleted) {
          finished.complete();
        }
      }

      void pumpWrites() {
        if (pumpingWrites) return;
        pumpingWrites = true;
        socket!.writeEventsEnabled = false;
        try {
          while (nextToSend < datagramCount) {
            final payload = expected[nextToSend]!;
            if (socket.send(payload) == 0) break;
            nextToSend++;
          }
          if (nextToSend != datagramCount) {
            socket.writeEventsEnabled = true;
          }
        } finally {
          pumpingWrites = false;
        }
      }

      subscription = socket.listen(
        (event) {
          if (event == RawSocketEvent.write) pumpWrites();
          if (event == RawSocketEvent.read) drainReads();
        },
        onError: finished.completeError,
      );

      expect(socket.send(expected[0]!), datagramSize);
      nextToSend = 1;
      expect(
        socket.send(expected[1]!),
        0,
        reason: 'the single plaintext output slot should be full',
      );
      pumpWrites();

      await _withInspectorDiagnostics(finished.future, harness);
      expect(nextToSend, datagramCount);
      for (final entry in expected.entries) {
        expect(received[entry.key], orderedEquals(entry.value));
      }
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 30)));
}

Future<int> _openBidirectionalStream(RawDatagramSecureSocket socket) async {
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (true) {
    final streamId = socket.openBidirectionalStream();
    if (streamId >= 0) return streamId;
    if (DateTime.now().isAfter(deadline)) {
      fail('Timed out waiting for a QUIC bidirectional stream');
    }
    await Future<void>.delayed(const Duration(milliseconds: 1));
  }
}

void _drainPeerStreams(
  RawDatagramSecureSocket socket,
  Set<int> peerStreams,
) {
  while (true) {
    final streamId = socket.acceptStream();
    if (streamId < 0) break;
    peerStreams.add(streamId);
  }
  for (final streamId in peerStreams.toList()) {
    while (true) {
      final chunk = socket.streamRead(streamId);
      if (chunk == null) break;
      if (chunk.isEmpty) {
        peerStreams.remove(streamId);
        break;
      }
    }
  }
}

Future<void> _waitUntil(
  bool Function() predicate, {
  String Function()? diagnostics,
}) async {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  while (!predicate()) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException(
        'Condition was not reached${diagnostics == null ? '' : ':\n${diagnostics()}'}',
      );
    }
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
}

Future<T> _withInspectorDiagnostics<T>(
  Future<T> future,
  _InspectorHarness harness,
) {
  return future.timeout(
    const Duration(seconds: 15),
    onTimeout: () => throw TimeoutException(
      'Timed out waiting for QUIC data.\n${harness.output.join('\n')}',
    ),
  );
}

class _InspectorHarness {
  _InspectorHarness(
    this.process,
    this.port,
    this.output,
    this.stdoutSubscription,
    this.stderrSubscription,
  );

  final Process process;
  final int port;
  final List<String> output;
  final StreamSubscription<String> stdoutSubscription;
  final StreamSubscription<String> stderrSubscription;

  static Future<_InspectorHarness> start(List<String> options) async {
    final process = await Process.start(
      Platform.resolvedExecutable,
      ['run', 'bin/quic_inspector.dart', '--port', '0', ...options],
      workingDirectory: Directory.current.path,
    );
    final output = <String>[];
    final portCompleter = Completer<int>();
    void onLine(String line) {
      output.add(line);
      const prefix = 'QUIC inspector listening on 127.0.0.1:';
      if (!portCompleter.isCompleted && line.startsWith(prefix)) {
        portCompleter.complete(int.parse(line.substring(prefix.length)));
      }
    }

    final stdoutSubscription = process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(onLine);
    final stderrSubscription = process.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(onLine);
    try {
      final port = await portCompleter.future.timeout(
        const Duration(seconds: 5),
      );
      return _InspectorHarness(
        process,
        port,
        output,
        stdoutSubscription,
        stderrSubscription,
      );
    } catch (_) {
      process.kill(ProcessSignal.sigkill);
      await stdoutSubscription.cancel();
      await stderrSubscription.cancel();
      rethrow;
    }
  }

  Future<RawDatagramSecureSocket> connect() {
    return RawDatagramSecureSocket.connect(
      '127.0.0.1',
      port,
      context: SecurityContext(withTrustedRoots: false),
      onBadCertificate: (_) => true,
      supportedProtocols: const ['h3'],
    ).timeout(const Duration(seconds: 10));
  }

  Future<void> waitForOutput(bool Function(String line) predicate) async {
    await _waitUntil(() => output.any(predicate));
  }

  Future<void> close() async {
    process.kill(ProcessSignal.sigterm);
    await process.exitCode.timeout(
      const Duration(seconds: 5),
      onTimeout: () {
        process.kill(ProcessSignal.sigkill);
        return process.exitCode;
      },
    );
    await stdoutSubscription.cancel();
    await stderrSubscription.cancel();
  }
}
