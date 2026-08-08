import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('uses the existing TCP adapter when HTTP/3 is not advertised', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) {
      request.response
        ..statusCode = HttpStatus.ok
        ..write('tcp-fallback')
        ..close();
    });
    final dio = Dio()
      ..httpClientAdapter = Http3Adapter(Http3ConnectionManager());
    try {
      final response = await dio.get<String>(
        'http://127.0.0.1:${server.port}/fallback',
      );

      expect(response.statusCode, HttpStatus.ok);
      expect(response.data, 'tcp-fallback');
    } finally {
      dio.close(force: true);
      await server.close(force: true);
    }
  });

  test('rejects unavailable HTTP/3 when fallback is disabled', () async {
    final dio = Dio()
      ..httpClientAdapter = Http3Adapter(
        Http3ConnectionManager(),
        allowFallback: false,
      );
    try {
      await expectLater(
        dio.get<void>('http://127.0.0.1/'),
        throwsA(isA<DioError>().having(
          (error) => error.error,
          'error',
          isA<Http3HandshakeUnavailableException>(),
        )),
      );
    } finally {
      dio.close(force: true);
    }
  });

  test('follows redirects per origin and removes cross-origin credentials',
      () async {
    final targetRequest = Completer<Map<String, String?>>();
    final target = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    target.listen((request) async {
      targetRequest.complete(<String, String?>{
        'authorization': request.headers.value(HttpHeaders.authorizationHeader),
        'cookie': request.headers.value(HttpHeaders.cookieHeader),
      });
      request.response
        ..statusCode = HttpStatus.ok
        ..write('redirect-target');
      await request.response.close();
    });
    final source = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    source.listen((request) async {
      request.response
        ..statusCode = HttpStatus.found
        ..headers.set(
          HttpHeaders.locationHeader,
          'http://127.0.0.1:${target.port}/target',
        );
      await request.response.close();
    });
    final dio = Dio()
      ..httpClientAdapter = Http3Adapter(Http3ConnectionManager());
    try {
      final response = await dio.get<String>(
        'http://127.0.0.1:${source.port}/start',
        options: Options(headers: const {
          HttpHeaders.authorizationHeader: 'Bearer secret',
          HttpHeaders.cookieHeader: 'session=secret',
        }),
      );

      expect(response.data, 'redirect-target');
      expect(response.redirects, hasLength(1));
      expect(response.redirects.single.statusCode, HttpStatus.found);
      expect(response.redirects.single.method, 'GET');
      expect(response.redirects.single.location.port, target.port);
      expect(response.isRedirect, isTrue);
      expect(
        await targetRequest.future,
        const {'authorization': null, 'cookie': null},
      );
    } finally {
      dio.close(force: true);
      await source.close(force: true);
      await target.close(force: true);
    }
  });

  test('rewrites POST to GET for 303 redirects', () async {
    final redirectedRequest = Completer<Map<String, String>>();
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      if (request.uri.path == '/start') {
        await request.drain<void>();
        request.response
          ..statusCode = HttpStatus.seeOther
          ..headers.set(HttpHeaders.locationHeader, '/target');
      } else {
        redirectedRequest.complete({
          'method': request.method,
          'body': await utf8.decoder.bind(request).join(),
        });
        request.response
          ..statusCode = HttpStatus.ok
          ..write('done');
      }
      await request.response.close();
    });
    final dio = Dio()
      ..httpClientAdapter = Http3Adapter(Http3ConnectionManager());
    try {
      final response = await dio.post<String>(
        'http://127.0.0.1:${server.port}/start',
        data: 'request-body',
      );

      expect(response.data, 'done');
      expect(
        await redirectedRequest.future,
        const {'method': 'GET', 'body': ''},
      );
    } finally {
      dio.close(force: true);
      await server.close(force: true);
    }
  });

  test('replays method and body for 307 redirects', () async {
    final redirectedRequest = Completer<Map<String, String>>();
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      final body = await utf8.decoder.bind(request).join();
      if (request.uri.path == '/start') {
        request.response
          ..statusCode = HttpStatus.temporaryRedirect
          ..headers.set(HttpHeaders.locationHeader, '/target');
      } else {
        redirectedRequest.complete({
          'method': request.method,
          'body': body,
        });
        request.response
          ..statusCode = HttpStatus.ok
          ..write('done');
      }
      await request.response.close();
    });
    final dio = Dio()
      ..httpClientAdapter = Http3Adapter(Http3ConnectionManager());
    try {
      final response = await dio.post<String>(
        'http://127.0.0.1:${server.port}/start',
        data: 'request-body',
      );

      expect(response.data, 'done');
      expect(
        await redirectedRequest.future,
        const {'method': 'POST', 'body': 'request-body'},
      );
    } finally {
      dio.close(force: true);
      await server.close(force: true);
    }
  });

  test('throws RedirectException when maxRedirects is exceeded', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      final hop = int.parse(request.uri.path.substring(1));
      request.response
        ..statusCode = HttpStatus.found
        ..headers.set(HttpHeaders.locationHeader, '/${hop + 1}');
      await request.response.close();
    });
    final dio = Dio()
      ..httpClientAdapter = Http3Adapter(Http3ConnectionManager());
    try {
      await expectLater(
        dio.get<void>(
          'http://127.0.0.1:${server.port}/0',
          options: Options(maxRedirects: 1),
        ),
        throwsA(
          isA<DioError>().having(
            (error) => error.error,
            'error',
            isA<RedirectException>(),
          ),
        ),
      );
    } finally {
      dio.close(force: true);
      await server.close(force: true);
    }
  });

  test('follows a redirect response received over HTTP/3', () async {
    final target = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    target.listen((request) async {
      request.response
        ..statusCode = HttpStatus.ok
        ..write('http3-redirect-target');
      await request.response.close();
    });
    final targetUri = 'http://127.0.0.1:${target.port}/target';
    final inspector = await _InspectorHarness.start([
      '--redirect-location',
      targetUri,
    ]);
    final manager = Http3ConnectionManager(
      preferHttp3WithoutAltSvc: true,
      onClientCreate: (_, setting) {
        setting.onBadCertificate = (_) => true;
      },
    );
    final dio = Dio()..httpClientAdapter = Http3Adapter(manager);
    try {
      final response = await dio.get<String>(
        'https://127.0.0.1:${inspector.port}/start',
      );

      expect(response.data, 'http3-redirect-target');
      expect(response.redirects, hasLength(1));
      expect(response.redirects.single.statusCode, HttpStatus.found);
      expect(response.redirects.single.location, Uri.parse(targetUri));
      expect(
        inspector.output,
        contains(
          startsWith('  server 1-rtt => h3 redirect stream=0 location='),
        ),
      );
    } finally {
      dio.close(force: true);
      await inspector.close();
      await target.close(force: true);
    }
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('attributes Alt-Svc to the redirected response origin', () async {
    final target = await _InspectorHarness.start([
      '--response-alt-svc',
      'h3=":443"; ma=60',
    ]);
    final targetUri = 'https://127.0.0.1:${target.port}/target';
    final source = await _InspectorHarness.start([
      '--redirect-location',
      targetUri,
    ]);
    final manager = Http3ConnectionManager(
      onClientCreate: (_, setting) {
        setting.onBadCertificate = (_) => true;
      },
    );
    final dio = Dio()..httpClientAdapter = Http3Adapter(manager);
    try {
      final response = await dio.get<String>(
        'https://127.0.0.1:${source.port}/start',
        options: Options(preferHttp3WithoutAltSvc: true),
      );

      expect(response.data, 'alt-svc-response');
      expect(
        manager.shouldAttemptHttp3(
          RequestOptions(
            path: 'https://127.0.0.1:${source.port}/another',
          ),
        ),
        isFalse,
      );
      expect(
        manager.shouldAttemptHttp3(
          RequestOptions(
            path: 'https://127.0.0.1:${target.port}/another',
          ),
        ),
        isTrue,
      );
    } finally {
      dio.close(force: true);
      await source.close();
      await target.close();
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
