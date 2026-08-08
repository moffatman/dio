import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  final serverPath = Platform.environment['QUICHE_SERVER'];

  test(
    'fetches from Cloudflare quiche and resumes with 0-RTT',
    () async {
      final harness = await _QuicheServerHarness.start(serverPath!);
      final manager = Http3ConnectionManager(
        preferHttp3WithoutAltSvc: true,
        onClientCreate: (_, settings) {
          settings.onBadCertificate = (_) => true;
        },
      );
      try {
        final firstOptions = RequestOptions(
          path: 'https://127.0.0.1:${harness.port}/stream-bytes/65536',
          method: 'GET',
        );
        final first = await manager.getConnection(firstOptions);
        expect(first, isNotNull);
        final firstResponse = await first!.fetch(firstOptions, null, null);
        expect(firstResponse.statusCode, 200);
        expect(firstResponse.headers['server'], contains('quiche'));
        _expectQuicheStreamBytes(await _collect(firstResponse), 65536);

        // quiche sends NewSessionTicket after the handshake. Give dart:io a
        // filter pass to publish the opaque resumption state to the manager.
        await Future<void>.delayed(const Duration(milliseconds: 100));
        await first.finish();

        final secondOptions = RequestOptions(
          path: 'https://127.0.0.1:${harness.port}/stream-bytes/4097',
          method: 'GET',
        );
        final second = await manager.getConnection(secondOptions);
        expect(second, isNotNull);
        expect(second!.isEarlyData, isTrue);
        final secondResponse = await second.fetch(secondOptions, null, null);
        expect(secondResponse.statusCode, 200);
        _expectQuicheStreamBytes(await _collect(secondResponse), 4097);
        expect(await second.handshakeComplete, isTrue);
        expect(second.earlyDataAccepted, isTrue);
        await second.finish();
      } catch (_) {
        stdout.writeln('quiche-server output:\n${harness.output.join('\n')}');
        rethrow;
      } finally {
        manager.close(force: true);
        await harness.close();
      }
    },
    skip: serverPath == null
        ? 'Set QUICHE_SERVER to a Cloudflare quiche-server binary.'
        : false,
    timeout: const Timeout(Duration(seconds: 30)),
  );
}

Future<Uint8List> _collect(ResponseBody response) async {
  final bytes = BytesBuilder(copy: false);
  await for (final chunk in response.stream) {
    bytes.add(chunk);
  }
  return bytes.takeBytes();
}

void _expectQuicheStreamBytes(Uint8List bytes, int length) {
  expect(bytes, hasLength(length));
  expect(bytes.every((byte) => byte == 0x57), isTrue);
}

class _QuicheServerHarness {
  _QuicheServerHarness(
    this.process,
    this.port,
    this.output,
    this.stdoutSubscription,
    this.stderrSubscription,
    this.root,
  );

  final Process process;
  final int port;
  final List<String> output;
  final StreamSubscription<String> stdoutSubscription;
  final StreamSubscription<String> stderrSubscription;
  final Directory root;

  static Future<_QuicheServerHarness> start(String serverPath) async {
    final server = File(serverPath);
    if (!server.existsSync()) {
      throw StateError('QUICHE_SERVER does not exist: $serverPath');
    }
    final resolvedServer = File(server.resolveSymbolicLinksSync());
    final repository = resolvedServer.parent.parent.parent;
    final certificate = File(
      Platform.environment['QUICHE_CERT'] ??
          '${repository.path}/apps/src/bin/cert.crt',
    );
    final privateKey = File(
      Platform.environment['QUICHE_KEY'] ??
          '${repository.path}/apps/src/bin/cert.key',
    );
    if (!certificate.existsSync() || !privateKey.existsSync()) {
      throw StateError(
        'Set QUICHE_CERT and QUICHE_KEY when the server binary is not in a '
        'Cloudflare quiche target directory.',
      );
    }

    final port = await _reserveUdpPort();
    final root = await Directory.systemTemp.createTemp('quiche-http3-root-');
    final process = await Process.start(
      resolvedServer.path,
      [
        '--listen',
        '127.0.0.1:$port',
        '--cert',
        certificate.path,
        '--key',
        privateKey.path,
        '--root',
        root.path,
        '--http-version',
        'HTTP/3',
        '--early-data',
        '--disable-gso',
        '--disable-pacing',
      ],
      environment: const {'RUST_LOG': 'info'},
    );
    final output = <String>[];
    final ready = Completer<void>();
    void onLine(String line) {
      output.add(line);
      if (!ready.isCompleted && line.contains('listening on 127.0.0.1:$port')) {
        ready.complete();
      }
    }

    final stdoutSubscription = process.stdout
        .transform(const SystemEncoding().decoder)
        .transform(const LineSplitter())
        .listen(onLine);
    final stderrSubscription = process.stderr
        .transform(const SystemEncoding().decoder)
        .transform(const LineSplitter())
        .listen(onLine);
    try {
      await Future.any<void>([
        ready.future,
        process.exitCode.then((code) {
          if (!ready.isCompleted) {
            throw StateError(
              'quiche-server exited with code $code:\n${output.join('\n')}',
            );
          }
        }),
      ]).timeout(const Duration(seconds: 10));
      return _QuicheServerHarness(
        process,
        port,
        output,
        stdoutSubscription,
        stderrSubscription,
        root,
      );
    } catch (_) {
      process.kill(ProcessSignal.sigkill);
      await stdoutSubscription.cancel();
      await stderrSubscription.cancel();
      await root.delete(recursive: true);
      rethrow;
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
    await root.delete(recursive: true);
  }
}

Future<int> _reserveUdpPort() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  socket.close();
  return port;
}
