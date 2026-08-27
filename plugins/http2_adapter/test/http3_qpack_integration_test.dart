import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('resumes response headers blocked on the QPACK encoder stream',
      () async {
    final harness = await _QpackInspectorHarness.start();
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, settings) {
        settings.onBadCertificate = (_) => true;
      },
    );
    final dio = Dio()
      ..httpClientAdapter = Http3Adapter(manager, allowFallback: false);
    try {
      final response = await dio.get<List<int>>(
        'https://127.0.0.1:${harness.port}/dynamic-qpack',
        options: Options(
          responseType: ResponseType.bytes,
          headers: const {'x-qpack-test': 'repeatable-value'},
        ),
      );
      expect(response.statusCode, 200);
      expect(response.headers.value('server'), 'qpack-inspector');
      expect(response.headers['set-cookie'], [
        'a=1; Path=/',
        'b=2; HttpOnly',
      ]);
      expect(
        utf8.decode(response.data!),
        'dynamic-qpack',
      );
      await harness.waitFor(
        (line) => line.contains('dynamic QPACK response stream=0'),
      );
      await harness.waitFor(
        (line) => line.contains('STREAM id=6 '),
      );
      await harness.waitFor(
        (line) => line.contains('STREAM id=10 '),
      );
    } finally {
      dio.close(force: true);
      await harness.close();
    }
  }, timeout: const Timeout(Duration(seconds: 20)));
}

class _QpackInspectorHarness {
  _QpackInspectorHarness(
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

  static Future<_QpackInspectorHarness> start() async {
    final process = await Process.start(
      Platform.resolvedExecutable,
      const [
        'run',
        'bin/quic_inspector.dart',
        '--port',
        '0',
        '--dynamic-qpack-response',
      ],
      workingDirectory: Directory.current.path,
    );
    final output = <String>[];
    final port = Completer<int>();
    void onLine(String line) {
      output.add(line);
      const prefix = 'QUIC inspector listening on 127.0.0.1:';
      if (!port.isCompleted && line.startsWith(prefix)) {
        port.complete(int.parse(line.substring(prefix.length)));
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
      return _QpackInspectorHarness(
        process,
        await port.future.timeout(const Duration(seconds: 5)),
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

  Future<void> waitFor(bool Function(String line) predicate) async {
    final deadline = DateTime.now().add(const Duration(seconds: 5));
    while (!output.any(predicate)) {
      if (DateTime.now().isAfter(deadline)) {
        fail('Inspector output did not contain the expected event.\n'
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
