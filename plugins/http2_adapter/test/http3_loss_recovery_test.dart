import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('retransmits the client Initial after PTO', () async {
    final inspector = await Process.start(
      Platform.resolvedExecutable,
      const [
        'run',
        'bin/quic_inspector.dart',
        '--port',
        '0',
        '--drop-first-client-datagram',
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
      socket.listen((_) {});

      expect(socket.selectedProtocol, 'h3');
      expect(
        output,
        contains(startsWith('dropped first client datagram length=')),
      );
    } finally {
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
