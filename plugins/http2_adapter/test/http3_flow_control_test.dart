import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

void main() {
  test('resumes a QUIC stream after peer flow-control updates', () async {
    final inspector = await Process.start(
      Platform.resolvedExecutable,
      const [
        'run',
        'bin/quic_inspector.dart',
        '--port',
        '0',
        '--initial-max-data',
        '16',
        '--initial-max-stream-data',
        '16',
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

      final data = Uint8List.fromList(List<int>.generate(64, (i) => i));
      final streamId = await _openBidirectionalStream(socket);

      socketSubscription = socket.listen((_) {});

      final firstWrite = socket.streamWrite(streamId, data);
      expect(firstWrite, data.length);

      await _waitForOutput(
        output,
        (line) => line.contains(
          'STREAM id=$streamId offset=0 length=16 fin=false',
        ),
      );
      await _waitForOutput(
        output,
        (line) => line.contains(
          'STREAM id=$streamId offset=16 length=48 fin=false',
        ),
      );
      expect(output, contains('  server 1-rtt => MAX_DATA 1048576'));
      expect(
        output,
        contains('  server 1-rtt => MAX_STREAM_DATA id=$streamId 524288'),
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

Future<void> _waitForOutput(
  List<String> output,
  bool Function(String line) predicate,
) async {
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (!output.any(predicate)) {
    if (DateTime.now().isAfter(deadline)) {
      fail('Timed out waiting for inspector output:\n${output.join('\n')}');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}
