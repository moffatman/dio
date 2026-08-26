import 'dart:async';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/src/redirect.dart';
import 'package:test/test.dart';

void main() {
  test('DioError from a redirected hop uses the original request options', () async {
    final original = RequestOptions(
      path: 'https://example.com/original',
      followRedirects: true,
    );
    var requests = 0;

    try {
      await fetchFollowingRedirects(
        fetchOne: (options, _, __) async {
          requests++;
          if (requests == 1) {
            return ResponseBody.fromString(
              '',
              302,
              headers: <String, List<String>>{
                'location': <String>['/redirected'],
              },
            );
          }
          final response = Response<void>(requestOptions: options);
          throw DioError(
            requestOptions: options,
            response: response,
            type: DioErrorType.connectTimeout,
          );
        },
        options: original,
        requestStream: null,
        cancelFuture: null,
      );
      fail('Expected a DioError');
    } on DioError catch (error) {
      expect(requests, 2);
      expect(identical(error.requestOptions, original), isTrue);
      expect(identical(error.response!.requestOptions, original), isTrue);
      expect(error.requestOptions.uri, original.uri);
    }
  });

  test('DioError from the final response stream uses original options', () async {
    final original = RequestOptions(
      path: 'https://example.com/original',
      followRedirects: true,
    );
    late RequestOptions internal;
    var requests = 0;
    final response = await fetchFollowingRedirects(
      fetchOne: (options, _, __) async {
        requests++;
        if (requests == 1) {
          return ResponseBody.fromString(
            '',
            302,
            headers: <String, List<String>>{
              'location': <String>['/redirected'],
            },
          );
        }
        internal = options;
        return ResponseBody(
          Stream<Uint8List>.error(
            DioError(
              requestOptions: options,
              type: DioErrorType.receiveTimeout,
            ),
          ),
          200,
        );
      },
      options: original,
      requestStream: null,
      cancelFuture: null,
    );

    expect(identical(internal, original), isFalse);
    expect(requests, 2);
    await expectLater(
      response.stream,
      emitsError(
        isA<DioError>()
            .having(
              (error) => identical(error.requestOptions, original),
              'uses original RequestOptions',
              isTrue,
            )
            .having(
              (error) => error.requestOptions.uri,
              'original URI',
              original.uri,
            ),
      ),
    );
  });

  test('DioError without a redirect keeps its request options', () async {
    final original = RequestOptions(
      path: 'https://example.com/original',
      followRedirects: true,
    );
    late RequestOptions internal;

    try {
      await fetchFollowingRedirects(
        fetchOne: (options, _, __) async {
          internal = options;
          throw DioError(
            requestOptions: options,
            type: DioErrorType.connectTimeout,
          );
        },
        options: original,
        requestStream: null,
        cancelFuture: null,
      );
      fail('Expected a DioError');
    } on DioError catch (error) {
      expect(identical(internal, original), isFalse);
      expect(identical(error.requestOptions, internal), isTrue);
      expect(identical(error.requestOptions, original), isFalse);
    }
  });

  test('stream error without a redirect keeps its request options', () async {
    final original = RequestOptions(
      path: 'https://example.com/original',
      followRedirects: true,
    );
    late RequestOptions internal;
    final response = await fetchFollowingRedirects(
      fetchOne: (options, _, __) async {
        internal = options;
        return ResponseBody(
          Stream<Uint8List>.error(
            DioError(
              requestOptions: options,
              type: DioErrorType.receiveTimeout,
            ),
          ),
          200,
        );
      },
      options: original,
      requestStream: null,
      cancelFuture: null,
    );

    await expectLater(
      response.stream,
      emitsError(
        isA<DioError>()
            .having(
              (error) => identical(error.requestOptions, internal),
              'keeps internal RequestOptions',
              isTrue,
            )
            .having(
              (error) => identical(error.requestOptions, original),
              'does not use original RequestOptions',
              isFalse,
            ),
      ),
    );
  });

  test('error interceptor sees original options after a redirected hop', () async {
    final originalUri = Uri.parse('https://example.com/original');
    final intercepted = Completer<RequestOptions>();
    final dio = Dio()..httpClientAdapter = _FailingRedirectAdapter();
    dio.interceptors.add(
      InterceptorsWrapper(
        onError: (error, handler) {
          intercepted.complete(error.requestOptions);
          handler.next(error);
        },
      ),
    );

    await expectLater(
      dio.getUri<void>(originalUri),
      throwsA(isA<DioError>()),
    );
    final requestOptions = await intercepted.future;
    expect(requestOptions.uri, originalUri);
    dio.close(force: true);
  });

  test('nested redirected requests retain their own original options', () async {
    final outerUri = Uri.parse('https://example.com/outer-start');
    final innerUri = Uri.parse('https://example.com/inner-start');
    final requestOptions = <Uri, RequestOptions>{};
    final responseOptions = <Uri, RequestOptions>{};
    late Dio dio;
    var nested = false;

    dio = Dio()..httpClientAdapter = _SuccessfulRedirectAdapter();
    dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) {
          requestOptions[options.uri] = options;
          handler.next(options);
        },
        onResponse: (response, handler) async {
          responseOptions[response.requestOptions.uri] = response.requestOptions;
          if (response.requestOptions.uri == outerUri && !nested) {
            nested = true;
            await dio.getUri<void>(innerUri);
          }
          handler.next(response);
        },
      ),
    );

    final outerResponse = await dio.getUri<void>(outerUri);
    expect(outerResponse.requestOptions.uri, outerUri);
    expect(responseOptions.keys, containsAll(<Uri>[outerUri, innerUri]));
    expect(
      identical(responseOptions[outerUri], requestOptions[outerUri]),
      isTrue,
    );
    expect(
      identical(responseOptions[innerUri], requestOptions[innerUri]),
      isTrue,
    );
    expect(identical(responseOptions[outerUri], responseOptions[innerUri]), isFalse);
    dio.close(force: true);
  });

  test('followRedirects false only fetches the original request', () async {
    final original = RequestOptions(
      path: 'https://example.com/original',
      followRedirects: false,
    );
    var requests = 0;
    final response = await fetchFollowingRedirects(
      fetchOne: (options, _, __) async {
        requests++;
        expect(identical(options, original), isTrue);
        return ResponseBody.fromString(
          'redirect',
          302,
          headers: <String, List<String>>{
            'location': <String>['/not-followed'],
          },
        );
      },
      options: original,
      requestStream: null,
      cancelFuture: null,
    );

    expect(requests, 1);
    expect(response.statusCode, 302);
    expect(response.redirects, isNull);
  });
}

class _FailingRedirectAdapter implements HttpClientAdapter {
  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  ) {
    var requests = 0;
    return fetchFollowingRedirects(
      fetchOne: (current, _, __) async {
        requests++;
        if (requests == 1) {
          return ResponseBody.fromString(
            '',
            302,
            headers: <String, List<String>>{
              'location': <String>['/redirected'],
            },
          );
        }
        throw DioError(
          requestOptions: current,
          type: DioErrorType.connectTimeout,
        );
      },
      options: options,
      requestStream: requestStream,
      cancelFuture: cancelFuture,
    );
  }

  @override
  void close({bool force = false}) {}
}

class _SuccessfulRedirectAdapter implements HttpClientAdapter {
  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  ) {
    return fetchFollowingRedirects(
      fetchOne: (current, _, __) async {
        if (current.uri.path.endsWith('-start')) {
          return ResponseBody.fromString(
            '',
            302,
            headers: <String, List<String>>{
              'location': <String>[
                current.uri.path.replaceFirst('-start', '-final'),
              ],
            },
          );
        }
        return ResponseBody.fromString('', 200);
      },
      options: options,
      requestStream: requestStream,
      cancelFuture: cancelFuture,
    );
  }

  @override
  void close({bool force = false}) {}
}
