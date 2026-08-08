import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

void main() {
  test('delivers RESET_STREAM and answers STOP_SENDING', () async {
    final inspector = await Process.start(
      Platform.resolvedExecutable,
      const [
        'run',
        'bin/quic_inspector.dart',
        '--port',
        '0',
        '--terminate-first-client-stream',
      ],
      workingDirectory: Directory.current.path,
    );
    final output = <String>[];
    final portCompleter = Completer<int>();
    final stdoutSubscription = inspector.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      output.add(line);
      const prefix = 'QUIC inspector listening on 127.0.0.1:';
      if (!portCompleter.isCompleted && line.startsWith(prefix)) {
        portCompleter.complete(int.parse(line.substring(prefix.length)));
      }
    });
    final stderrSubscription = inspector.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(output.add);

    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? socketSubscription;
    try {
      final port = await portCompleter.future.timeout(
        const Duration(seconds: 5),
      );
      socket = await RawDatagramSecureSocket.connect(
        '127.0.0.1',
        port,
        context: SecurityContext(withTrustedRoots: false),
        onBadCertificate: (_) => true,
        supportedProtocols: const ['h3'],
      ).timeout(const Duration(seconds: 10));

      final streamId = await _openBidirectionalStream(socket);
      final peerReadError = Completer<int>();
      final peerWriteError = Completer<int>();
      final peerStreamError = Completer<int>();
      socketSubscription = socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        if (!peerReadError.isCompleted) {
          final errorCode = socket!.streamReadErrorCode(streamId);
          if (errorCode != null) {
            peerReadError.complete(errorCode);
          }
        }
        if (!peerWriteError.isCompleted) {
          final errorCode = socket!.streamWriteErrorCode(streamId);
          if (errorCode != null) {
            peerWriteError.complete(errorCode);
          }
        }
        while (true) {
          final acceptedStreamId = socket!.acceptStream();
          if (acceptedStreamId < 0) break;
          final errorCode = socket.streamReadErrorCode(acceptedStreamId);
          if (errorCode != null && !peerStreamError.isCompleted) {
            peerStreamError.complete(errorCode);
          } else {
            while (socket.streamRead(acceptedStreamId) != null) {}
          }
        }
      });

      final data = Uint8List.fromList(List<int>.generate(64, (i) => i));
      expect(socket.streamWrite(streamId, data), data.length);
      expect(
        await peerReadError.future.timeout(const Duration(seconds: 5)),
        42,
      );
      expect(
        await peerWriteError.future.timeout(const Duration(seconds: 5)),
        43,
      );
      expect(socket.streamReadErrorCode(streamId), isNull);
      expect(socket.streamWriteErrorCode(streamId), isNull);
      expect(
        await peerStreamError.future.timeout(const Duration(seconds: 5)),
        44,
      );

      await _waitForOutput(
        output,
        '  frame@0 RESET_STREAM id=$streamId error=43 finalSize=64',
      );
      expect(
        output,
        contains('  server 1-rtt => STOP_SENDING id=$streamId error=43'),
      );
      await _waitForOutput(
        output,
        '  frame@0 MAX_STREAMS_UNI maximum=101',
      );
    } finally {
      await socketSubscription?.cancel();
      await socket?.close();
      inspector.kill(ProcessSignal.sigterm);
      await inspector.exitCode.timeout(
        const Duration(seconds: 5),
        onTimeout: () {
          inspector.kill(ProcessSignal.sigkill);
          return inspector.exitCode;
        },
      );
      await stdoutSubscription.cancel();
      await stderrSubscription.cancel();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));
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

Future<void> _waitForOutput(List<String> output, String expected) async {
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (!output.contains(expected)) {
    if (DateTime.now().isAfter(deadline)) {
      fail('Did not observe "$expected".\n${output.join('\n')}');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}
