import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';

typedef SingleRequestFetcher = Future<ResponseBody> Function(
  RequestOptions options,
  Stream<Uint8List>? requestStream,
  Future? cancelFuture,
);

const _redirectStatusCodes = <int>{
  HttpStatus.movedPermanently,
  HttpStatus.found,
  HttpStatus.seeOther,
  HttpStatus.temporaryRedirect,
  HttpStatus.permanentRedirect,
};

Future<ResponseBody> fetchFollowingRedirects({
  required SingleRequestFetcher fetchOne,
  required RequestOptions options,
  required Stream<Uint8List>? requestStream,
  required Future? cancelFuture,
}) async {
  if (!options.followRedirects) {
    return fetchOne(options, requestStream, cancelFuture);
  }

  final replayBody = requestStream == null ? null : <Uint8List>[];
  final initialBody = requestStream?.map((chunk) {
    final copy = Uint8List.fromList(chunk);
    replayBody!.add(copy);
    return copy;
  });
  var sendBody = initialBody;
  var bodyAvailable = replayBody != null;
  var current = options.copyWith(followRedirects: false);
  final redirects = <RedirectRecord>[];
  final visited = <String>{_redirectKey(current.method, current.uri)};

  while (true) {
    final response = await fetchOne(
      current,
      sendBody,
      cancelFuture,
    );
    final statusCode = response.statusCode;
    if (statusCode == null || !_redirectStatusCodes.contains(statusCode)) {
      return _withRedirects(response, redirects);
    }

    final location = _headerValue(
      response.headers,
      HttpHeaders.locationHeader,
    );
    if (location == null) {
      await _cancelRedirectResponse(response);
      throw RedirectException(
        'Server response has no Location header for redirect',
        _redirectInfo(redirects),
      );
    }

    late final Uri target;
    try {
      target = current.uri.resolve(location);
    } on FormatException {
      await _cancelRedirectResponse(response);
      throw RedirectException(
        'Server response has an invalid Location header: $location',
        _redirectInfo(redirects),
      );
    }

    final nextMethod = _redirectMethod(current.method, statusCode);
    final record = RedirectRecord(statusCode, nextMethod, target);
    if (redirects.length >= options.maxRedirects) {
      await _cancelRedirectResponse(response);
      throw RedirectException(
        'Redirect limit exceeded',
        _redirectInfo(<RedirectRecord>[...redirects, record]),
      );
    }
    if (!visited.add(_redirectKey(nextMethod, target))) {
      await _cancelRedirectResponse(response);
      throw RedirectException(
        'Redirect loop detected',
        _redirectInfo(<RedirectRecord>[...redirects, record]),
      );
    }

    await _cancelRedirectResponse(response);
    redirects.add(record);

    final dropsBody = nextMethod != current.method.toUpperCase();
    if (dropsBody) bodyAvailable = false;
    sendBody = !bodyAvailable || replayBody == null
        ? null
        : Stream<Uint8List>.fromIterable(replayBody);
    final headers = Map<String, dynamic>.of(current.headers);
    if (dropsBody) {
      _removeHeaders(headers, const <String>{
        Headers.contentLengthHeader,
        Headers.contentTypeHeader,
        HttpHeaders.contentEncodingHeader,
        HttpHeaders.contentLanguageHeader,
        HttpHeaders.contentLocationHeader,
        HttpHeaders.transferEncodingHeader,
      });
    }
    if (!_sameOrigin(current.uri, target)) {
      _removeHeaders(headers, const <String>{
        HttpHeaders.authorizationHeader,
        HttpHeaders.cookieHeader,
        HttpHeaders.hostHeader,
        'proxy-authorization',
      });
    }

    current = current.copyWith(
      baseUrl: '',
      path: target.toString(),
      queryParameters: const <String, dynamic>{},
      method: nextMethod,
      headers: headers,
      followRedirects: false,
      maxRedirects: options.maxRedirects - redirects.length,
    );
  }
}

String _redirectKey(String method, Uri uri) {
  return '${method.toUpperCase()} ${uri.replace(fragment: '')}';
}

String _redirectMethod(String method, int statusCode) {
  final normalized = method.toUpperCase();
  if (statusCode == HttpStatus.seeOther &&
      normalized != 'GET' &&
      normalized != 'HEAD') {
    return 'GET';
  }
  if ((statusCode == HttpStatus.movedPermanently ||
          statusCode == HttpStatus.found) &&
      normalized == 'POST') {
    return 'GET';
  }
  return normalized;
}

String? _headerValue(Map<String, List<String>> headers, String name) {
  final normalized = name.toLowerCase();
  for (final entry in headers.entries) {
    if (entry.key.toLowerCase() == normalized && entry.value.isNotEmpty) {
      return entry.value.first;
    }
  }
  return null;
}

void _removeHeaders(Map<String, dynamic> headers, Set<String> names) {
  final normalized = names.map((name) => name.toLowerCase()).toSet();
  headers.removeWhere((name, _) => normalized.contains(name.toLowerCase()));
}

bool _sameOrigin(Uri first, Uri second) {
  int effectivePort(Uri uri) {
    if (uri.hasPort) return uri.port;
    return uri.scheme == 'https' ? 443 : 80;
  }

  return first.scheme.toLowerCase() == second.scheme.toLowerCase() &&
      first.host.toLowerCase() == second.host.toLowerCase() &&
      effectivePort(first) == effectivePort(second);
}

Future<void> _cancelRedirectResponse(ResponseBody response) async {
  final subscription = response.stream.listen(
    null,
    onError: (Object _, StackTrace __) {},
  );
  await subscription.cancel();
}

ResponseBody _withRedirects(
  ResponseBody response,
  List<RedirectRecord> redirects,
) {
  if (redirects.isEmpty) return response;
  final result = ResponseBody(
    response.stream,
    response.statusCode,
    headers: response.headers,
    statusMessage: response.statusMessage,
    redirects: List<RedirectRecord>.unmodifiable(redirects),
    isRedirect: true,
  );
  result.extra.addAll(response.extra);
  return result;
}

List<RedirectInfo> _redirectInfo(List<RedirectRecord> redirects) {
  return redirects
      .map<RedirectInfo>(
        (record) => _HttpRedirectInfo(
          record.statusCode,
          record.method,
          record.location,
        ),
      )
      .toList(growable: false);
}

class _HttpRedirectInfo implements RedirectInfo {
  const _HttpRedirectInfo(this.statusCode, this.method, this.location);

  @override
  final int statusCode;

  @override
  final String method;

  @override
  final Uri location;
}
