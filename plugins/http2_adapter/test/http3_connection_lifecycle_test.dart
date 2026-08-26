import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('uses native UDP packet I/O', () async {
    final harness = await _InspectorHarness.start(const []);
    RawDatagramSecureSocket? socket;
    try {
      final connected = await harness.connect(useNativeUdp: true);
      socket = connected;
      expect(connected.isHandshakeComplete, isTrue);
      expect(connected.selectedProtocol, 'h3');
    } finally {
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('races QUIC handshakes across address families', () async {
    final harness = await _InspectorHarness.start(const ['--listen-ipv6']);
    RawDatagramSecureSocket? socket;
    try {
      socket = await harness.connect(host: 'localhost');
      expect(socket.remoteAddress.type, InternetAddressType.IPv6);
      expect(socket.isHandshakeComplete, isTrue);
    } finally {
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('sends a precise transport error for invalid stream flow control',
      () async {
    final harness = await _InspectorHarness.start(const [
      '--send-flow-control-violation',
    ]);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      final error = Completer<Object>();
      subscription = socket.listen(
        (_) {},
        onError: (Object value) {
          if (!error.isCompleted) error.complete(value);
        },
      );
      await harness.waitForOutput(
        (output) => output.any(
          (line) =>
              line.contains('CONNECTION_CLOSE transport error=3') &&
              line.contains('frame=14') &&
              line.contains('STREAM exceeds stream flow control'),
        ),
      );
      final exception = await error.future.timeout(const Duration(seconds: 5));
      expect(exception, isA<QuicConnectionException>());
      final termination = (exception as QuicConnectionException).termination;
      expect(termination.type, QuicConnectionTerminationType.transportClose);
      expect(termination.errorCode, 0x03);
      expect(termination.frameType, 0x0e);
      expect(termination.reason, 'STREAM exceeds stream flow control');
      expect(socket.termination, same(termination));
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('surfaces a peer HTTP/3 application close', () async {
    final harness = await _InspectorHarness.start(const [
      '--close-after-handshake',
    ]);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      final error = Completer<Object>();
      subscription = socket.listen(
        (_) {},
        onError: (Object value) {
          if (!error.isCompleted) error.complete(value);
        },
      );

      final exception = await error.future.timeout(const Duration(seconds: 5));
      expect(exception, isA<QuicConnectionException>());
      final termination = (exception as QuicConnectionException).termination;
      expect(
        termination.type,
        QuicConnectionTerminationType.applicationClose,
      );
      expect(termination.errorCode, 0x107);
      expect(termination.frameType, isNull);
      expect(termination.reason, 'inspector close');
      expect(socket.termination, same(termination));
      expect(
        harness.output,
        contains(startsWith(
          '  server 1-rtt => CONNECTION_CLOSE application',
        )),
      );
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('enforces the negotiated QUIC idle timeout', () async {
    final harness = await _InspectorHarness.start(const [
      '--max-idle-timeout',
      '100',
    ]);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      final error = Completer<Object>();
      subscription = socket.listen(
        (_) {},
        onError: (Object value) {
          if (!error.isCompleted) error.complete(value);
        },
      );

      final exception = await error.future.timeout(const Duration(seconds: 5));
      expect(exception, isA<QuicConnectionException>());
      final termination = (exception as QuicConnectionException).termination;
      expect(termination.type, QuicConnectionTerminationType.idleTimeout);
      expect(termination.errorCode, 0);
      expect(termination.frameType, isNull);
      expect(termination.reason, 'idle timeout');
      expect(socket.termination, same(termination));
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('preserves a peer close through the HTTP/3 manager', () async {
    final harness = await _InspectorHarness.start(const [
      '--close-after-handshake',
    ]);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/',
        method: 'GET',
      );
      final connection = await manager.getConnection(options);
      expect(connection, isNotNull);
      await expectLater(
        connection!.fetch(options, null, null),
        throwsA(
          isA<Http3ConnectionTerminatedException>()
              .having(
                (error) => error.termination.type,
                'type',
                QuicConnectionTerminationType.applicationClose,
              )
              .having(
                (error) => error.termination.errorCode,
                'errorCode',
                0x107,
              )
              .having(
                (error) => error.termination.reason,
                'reason',
                'inspector close',
              ),
        ),
      );
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('retransmits a local close during the QUIC closing period', () async {
    final harness = await _InspectorHarness.start(const [
      '--probe-client-close',
    ]);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      subscription = socket.listen((_) {});

      await socket
          .close(errorCode: 0x42, reason: 'client close')
          .timeout(const Duration(seconds: 10));

      expect(
        harness.output,
        contains('  server 1-rtt => PING after client CONNECTION_CLOSE'),
      );
      await harness.waitForOutput(
        (output) => output.where(_isConnectionCloseFrame).length >= 2,
      );
      final closeFrames = harness.output.where(_isConnectionCloseFrame);
      expect(closeFrames.length, greaterThanOrEqualTo(2));
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('reuses NEW_TOKEN on the next connection to the origin', () async {
    final harness = await _InspectorHarness.start(const ['--new-token']);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/',
        method: 'GET',
      );
      final first = await manager.getConnection(options);
      expect(first, isNotNull);
      await harness.waitForOutput(
        (output) =>
            output.any((line) => line.contains('server 1-rtt => NEW_TOKEN')),
      );
      await Future<void>.delayed(const Duration(milliseconds: 50));
      await first!.finish();

      final second = await manager.getConnection(options);
      expect(second, isNotNull);
      await harness.waitForOutput(
        (output) => output.any(
          (line) => line.contains(
            'client Initial token=696e73706563746f722d6e65772d746f6b656e',
          ),
        ),
      );
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('migrates an HTTP/3 connection to the peer preferred address', () async {
    final harness = await _InspectorHarness.start(const [
      '--preferred-address',
    ]);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/',
        method: 'GET',
      );
      final connection = await manager.getConnection(options);
      expect(connection, isNotNull);
      final preferredPort = await harness.preferredPort();
      expect(connection!.remoteAddress.address, '127.0.0.1');
      expect(connection.remotePort, preferredPort);
      await harness.waitForOutput(
        (output) =>
            output.any((line) => line.contains('PATH_CHALLENGE')) &&
            output.any(
                (line) => line.contains('server 1-rtt => PATH_RESPONSE')) &&
            output.any(
                (line) => line.contains('via serverPort=$preferredPort')) &&
            output.any(
                (line) => line.contains('short dcid[8]=e0e1e2e3e4e5e6e7')) &&
            output.any(
                (line) => line.contains('RETIRE_CONNECTION_ID sequence=0')),
      );
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('sends a replay-safe request in accepted 0-RTT data', () async {
    final harness = await _InspectorHarness.start(const []);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/early',
        method: 'GET',
      );
      final first = await manager.getConnection(options);
      expect(first, isNotNull);
      await harness.waitForOutput(
        (output) => output.any(
          (line) => line.contains('server tls => application CRYPTO'),
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await first!.finish();

      final second = await manager.getConnection(options);
      expect(second, isNotNull);
      expect(second!.isEarlyData, isTrue);
      final fetch = second.fetch(options, null, null).then<void>(
            (_) {},
            onError: (_) {},
          );
      await harness.waitForOutput(
        (output) =>
            output.any((line) => line.contains('type=0-RTT')) &&
            output.any(
              (line) => line.contains('server <= 0-RTT accepted=true'),
            ) &&
            output.any((line) => line.contains('STREAM id=0')),
      );
      expect(await second.handshakeComplete, isTrue);
      expect(second.earlyDataAccepted, isTrue);
      await second.finish();
      await fetch;
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('replays rejected 0-RTT request data after the handshake', () async {
    final harness = await _InspectorHarness.start(const [
      '--reject-resumed-early-data',
    ]);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/early-rejected',
        method: 'GET',
      );
      final first = await manager.getConnection(options);
      expect(first, isNotNull);
      await harness.waitForOutput(
        (output) => output.any(
          (line) => line.contains('server tls => application CRYPTO'),
        ),
      );
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await first!.finish();

      final second = await manager.getConnection(options);
      expect(second, isNotNull);
      expect(second!.isEarlyData, isTrue);
      final fetch = second.fetch(options, null, null).then<void>(
            (_) {},
            onError: (_) {},
          );
      await harness.waitForOutput(
        (output) => output.any((line) => line.contains('type=0-RTT')),
      );
      expect(await second.handshakeComplete, isFalse);
      expect(second.earlyDataAccepted, isFalse);
      await harness.waitForOutput(
        (output) =>
            output.any(
              (line) => line.contains('server <= 1-RTT streams='),
            ) &&
            output.any((line) => line.contains('STREAM id=0')),
      );
      await second.finish();
      await fetch;
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('drains a GOAWAY connection and opens a replacement', () async {
    final harness = await _InspectorHarness.start(const [
      '--dynamic-qpack-response',
      '--goaway-after-first-request',
    ]);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/goaway',
        method: 'GET',
      );
      final first = await manager.getConnection(options);
      expect(first, isNotNull);

      final firstResponse = await first!.fetch(options, null, null).timeout(
            const Duration(seconds: 5),
            onTimeout: () => throw StateError(
              'Timed out waiting for first response:\n${harness.output.join('\n')}',
            ),
          );
      expect(
        utf8.decode((await firstResponse.stream.toList().timeout(
                  const Duration(seconds: 5),
                  onTimeout: () => throw StateError(
                    'Timed out draining first response:\n'
                    '${harness.output.join('\n')}',
                  ),
                ))
            .expand((e) => e)
            .toList()),
        'dynamic-qpack',
      );
      await harness.waitForOutput(
        (output) => output.any((line) => line.contains('h3 GOAWAY id=4')),
      );
      await _waitFor(() => !first.canAcceptRequests);

      final second = await manager.getConnection(options);
      expect(second, isNotNull);
      expect(second, isNot(same(first)));
      final secondResponse = await second!.fetch(options, null, null).timeout(
            const Duration(seconds: 5),
            onTimeout: () => throw StateError(
              'Timed out waiting for replacement response:\n'
              '${harness.output.join('\n')}',
            ),
          );
      expect(
        utf8.decode(
          (await secondResponse.stream.toList()).expand((e) => e).toList(),
        ),
        'dynamic-qpack',
      );
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('retries a request rejected by GOAWAY on a new connection', () async {
    final harness = await _InspectorHarness.start(const [
      '--dynamic-qpack-response',
      '--reject-first-request-with-goaway',
    ]);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/goaway-retry',
        method: 'GET',
      );

      final response = await manager.fetch(
        options,
        null,
        null,
        allowFallback: false,
      );
      expect(
        utf8.decode(
          (await response.stream.toList()).expand((e) => e).toList(),
        ),
        'dynamic-qpack',
      );
      expect(
        harness.output,
        contains(contains('server 1-rtt => h3 GOAWAY id=0')),
      );
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('closes a native UDP connection after its response becomes idle',
      () async {
    final harness = await _InspectorHarness.start(const [
      '--dynamic-qpack-response',
    ]);
    final manager = Http3ConnectionManager(
      idleTimeout: 100,
      preferHttp3WithoutAltSvc: true,
      useNativeUdp: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/idle',
        method: 'GET',
      );
      final connection = await manager.getConnection(options);
      expect(connection, isNotNull);

      final response = await connection!.fetch(options, null, null);
      expect(
        utf8.decode(
          (await response.stream.toList()).expand((part) => part).toList(),
        ),
        'dynamic-qpack',
      );

      await _waitFor(() => !connection.isOpen);
    } finally {
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('accepts a complete response terminated with H3_NO_ERROR', () async {
    final harness = await _InspectorHarness.start(const [
      '--complete-response-reset-no-error',
    ]);
    final requestBodyCancelled = Completer<void>();
    final requestBody = StreamController<Uint8List>(
      onCancel: requestBodyCancelled.complete,
    );
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/no-error-reset',
        method: 'POST',
      );
      final connection = await manager.getConnection(options);
      expect(connection, isNotNull);

      final response = await connection!
          .fetch(options, requestBody.stream, null)
          .timeout(const Duration(seconds: 5));
      expect(response.statusCode, 200);
      expect(await response.stream.toList(), isEmpty);
      await requestBodyCancelled.future.timeout(const Duration(seconds: 5));
      expect(connection.isOpen, isTrue);
      expect(
        harness.output,
        contains(contains('complete response then RESET_STREAM id=0 error=256')),
      );
      expect(
        harness.output,
        contains(contains('STOP_SENDING id=0 error=256')),
      );
    } finally {
      await requestBody.close();
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('cancels both directions of an HTTP/3 request stream', () async {
    final harness = await _InspectorHarness.start(const []);
    final requestBody = StreamController<Uint8List>();
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    try {
      final options = RequestOptions(
        path: 'https://127.0.0.1:${harness.port}/cancel',
        method: 'POST',
      );
      final connection = await manager.getConnection(options);
      expect(connection, isNotNull);
      final cancel = Completer<void>();
      final response = connection!.fetch(
        options,
        requestBody.stream,
        cancel.future,
      );

      await harness.waitForOutput(
        (output) => output.any(
          (line) => line.contains('STREAM id=0') && line.contains('length='),
        ),
      );
      cancel.complete();

      await expectLater(
        response.timeout(const Duration(seconds: 5)),
        throwsA(
          isA<Http3RequestCancelledException>().having(
            (error) => error.streamId,
            'streamId',
            0,
          ),
        ),
      );
      await harness.waitForOutput(
        (output) =>
            output.any((line) => line.contains(
                  'RESET_STREAM id=0 error=268',
                )) &&
            output.any((line) => line.contains(
                  'STOP_SENDING id=0 error=268',
                )),
      );
      expect(connection.isOpen, isTrue);
    } finally {
      await requestBody.close();
      manager.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));
}

Future<void> _waitFor(bool Function() predicate) async {
  final deadline = DateTime.now().add(const Duration(seconds: 2));
  while (!predicate()) {
    if (DateTime.now().isAfter(deadline)) {
      throw StateError('Timed out waiting for condition');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

bool _isConnectionCloseFrame(String line) {
  return line.startsWith('  frame@') && line.contains('CONNECTION_CLOSE');
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
      '/Users/callum/Code/flutter/bin/dart',
      ['run', 'bin/quic_inspector.dart', '--port', '0', ...options],
      workingDirectory: Directory.current.path,
    );
    final output = <String>[];
    final port = Completer<int>();
    final stdoutSubscription = process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      print('stdout: $line');
      output.add(line);
      const prefix = 'QUIC inspector listening on ';
      if (!port.isCompleted && line.startsWith(prefix)) {
        port.complete(int.parse(line.substring(line.lastIndexOf(':') + 1)));
      }
    });
    final stderrSubscription = process.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      print('stderr: $line');
      output.add(line);
    });
    return _InspectorHarness(
      process,
      await port.future.timeout(const Duration(seconds: 5)),
      output,
      stdoutSubscription,
      stderrSubscription,
    );
  }

  Future<RawDatagramSecureSocket> connect({
    String host = '127.0.0.1',
    bool useNativeUdp = false,
  }) {
    return RawDatagramSecureSocket.connect(
      host,
      port,
      context: SecurityContext(withTrustedRoots: false),
      onBadCertificate: (_) => true,
      supportedProtocols: const ['h3'],
      useNativeUdp: useNativeUdp,
    ).timeout(const Duration(seconds: 10));
  }

  Future<int> preferredPort() async {
    const prefix = 'QUIC inspector preferred address 127.0.0.1:';
    await waitForOutput(
        (lines) => lines.any((line) => line.startsWith(prefix)));
    final line = output.firstWhere((line) => line.startsWith(prefix));
    return int.parse(line.substring(prefix.length));
  }

  Future<void> waitForOutput(
    bool Function(List<String> output) predicate,
  ) async {
    final deadline = DateTime.now().add(const Duration(seconds: 2));
    while (!predicate(output)) {
      if (DateTime.now().isAfter(deadline)) {
        throw StateError('Timed out waiting for inspector output:\n'
            '${output.join('\n')}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
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
