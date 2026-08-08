import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('bounds QUIC connection setup with timeout', () async {
    final blackhole =
        await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
    final subscription = blackhole.listen((event) {
      if (event == RawSocketEvent.read) {
        while (blackhole.receive() != null) {}
      }
    });

    try {
      final stopwatch = Stopwatch()..start();
      await expectLater(
        RawDatagramSecureSocket.connect(
          InternetAddress.loopbackIPv4,
          blackhole.port,
          context: SecurityContext(withTrustedRoots: false),
          onBadCertificate: (_) => true,
          useNativeUdp: true,
          timeout: const Duration(milliseconds: 100),
        ),
        throwsA(isA<SocketException>()),
      );
      expect(stopwatch.elapsed, lessThan(const Duration(seconds: 2)));

      // Keep the test zone alive to catch filter work completing after timeout.
      await Future<void>.delayed(const Duration(milliseconds: 250));
    } finally {
      await subscription.cancel();
      blackhole.close();
    }
  });

  test('terminates when Version Negotiation excludes QUIC v1', () async {
    final harness = await _InspectorHarness.start(const [
      '--version-negotiation',
    ]);
    try {
      await expectLater(
        harness.connect(),
        throwsA(
          isA<QuicConnectionException>().having(
            (error) => error.termination.type,
            'type',
            QuicConnectionTerminationType.versionNegotiation,
          ),
        ),
      );
      expect(
        harness.output,
        contains(startsWith('  server => VERSION_NEGOTIATION')),
      );
    } finally {
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('ignores Version Negotiation that includes QUIC v1', () async {
    final harness = await _InspectorHarness.start(const [
      '--version-negotiation',
      '--version-negotiation-includes-v1',
    ]);
    RawDatagramSecureSocket? socket;
    try {
      socket = await harness.connect();
      expect(socket.selectedProtocol, 'h3');
      expect(
        harness.output,
        contains(startsWith('  server => VERSION_NEGOTIATION includesV1=true')),
      );
    } finally {
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('restarts the Initial flight after an authenticated Retry', () async {
    final harness = await _InspectorHarness.start(const ['--retry']);
    RawDatagramSecureSocket? socket;
    try {
      try {
        socket = await harness.connect();
      } on TimeoutException {
        throw StateError(
            'Retry handshake timed out:\n${harness.output.join('\n')}');
      }
      expect(socket.selectedProtocol, 'h3');
      expect(harness.output, contains(startsWith('  server => RETRY')));
      expect(harness.output, contains('  retried Initial token validated'));
    } finally {
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('detects a stateless reset using an authenticated reset token',
      () async {
    final harness = await _InspectorHarness.start(const [
      '--stateless-reset-after-handshake',
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
      expect(
        (exception as QuicConnectionException).termination.type,
        QuicConnectionTerminationType.statelessReset,
      );
      expect(
        harness.output,
        contains(startsWith('  server => STATELESS_RESET')),
      );
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('retires connection IDs and answers PATH_CHALLENGE', () async {
    final harness = await _InspectorHarness.start(const [
      '--rotate-connection-id',
      '--path-challenge-after-handshake',
    ]);
    RawDatagramSecureSocket? socket;
    StreamSubscription<RawSocketEvent>? subscription;
    try {
      socket = await harness.connect();
      subscription = socket.listen((_) {});
      await harness.waitForOutput(
        (output) =>
            output.any((line) => line.contains('RETIRE_CONNECTION_ID')) &&
            output.any((line) => line.contains('PATH_RESPONSE')) &&
            output
                .any((line) => line.contains('short dcid[8]=a0a1a2a3a4a5a6a7')),
      );
    } finally {
      await subscription?.cancel();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('validates a new UDP path before changing the active connection',
      () async {
    final harness = await _InspectorHarness.start(const [
      '--rotate-connection-id',
    ]);
    RawDatagramSecureSocket? socket;
    RawDatagramSocket? replacement;
    try {
      socket = await harness.connect();
      await harness.waitForOutput(
        (output) => output.any(
          (line) => line.contains('NEW_CONNECTION_ID sequence=1'),
        ),
      );

      final oldPort = socket.port;
      replacement =
          await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
      final newPort = replacement.port;
      await socket
          .migrate(
            socket: replacement,
          )
          .timeout(const Duration(seconds: 10));

      expect(newPort, isNot(oldPort));
      expect(socket.port, newPort);
      expect(socket.remotePort, harness.port);
      await harness.waitForOutput(
        (output) =>
            output.any((line) => line.contains('PATH_CHALLENGE')) &&
            output.any(
                (line) => line.contains('server 1-rtt => PATH_RESPONSE')) &&
            output.any((line) => line == 'datagram from 127.0.0.1:$newPort'),
      );
      replacement = null; // Ownership moved to RawDatagramSecureSocket.
    } finally {
      replacement?.close();
      await socket?.close();
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));
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
    final port = Completer<int>();
    final stdoutSubscription = process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      output.add(line);
      const prefix = 'QUIC inspector listening on 127.0.0.1:';
      if (!port.isCompleted && line.startsWith(prefix)) {
        port.complete(int.parse(line.substring(prefix.length)));
      }
    });
    final stderrSubscription = process.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(output.add);
    return _InspectorHarness(
      process,
      await port.future.timeout(const Duration(seconds: 5)),
      output,
      stdoutSubscription,
      stderrSubscription,
    );
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

  Future<void> waitForOutput(
    bool Function(List<String> output) predicate,
  ) async {
    final deadline = DateTime.now().add(const Duration(seconds: 5));
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
