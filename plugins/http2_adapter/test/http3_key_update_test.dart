import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

void main() {
  test('receives a stream after the peer updates 1-RTT keys', () async {
    final inspector = await Process.start(
      Platform.resolvedExecutable,
      const [
        'run',
        'bin/quic_inspector.dart',
        '--port',
        '0',
        '--key-update-after-handshake',
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

      final updatedStream = Completer<List<int>>();
      final acceptedStreams = <int>{};
      final bytes = <int>[];
      socketSubscription = socket.listen((event) {
        if (event != RawSocketEvent.read) return;
        while (true) {
          final streamId = socket!.acceptStream();
          if (streamId < 0) break;
          acceptedStreams.add(streamId);
        }
        for (final streamId in acceptedStreams) {
          while (true) {
            final data = socket.streamRead(streamId);
            if (data == null) break;
            if (streamId == 7) bytes.addAll(data);
          }
          if (streamId == 7 &&
              bytes.length == 'key-update'.length &&
              !updatedStream.isCompleted) {
            updatedStream.complete(List<int>.of(bytes));
          }
        }
      });

      expect(
        utf8.decode(
          await updatedStream.future.timeout(const Duration(seconds: 5)),
        ),
        'key-update',
      );
      expect(
        output,
        contains(startsWith('  server 1-rtt => STREAM id=7 keyPhase=1')),
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
