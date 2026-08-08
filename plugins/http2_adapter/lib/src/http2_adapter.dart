import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/adapter.dart';
import 'package:dio/dio.dart';
import 'package:http2/http2.dart';

import 'redirect.dart';

part 'client_setting.dart';
part 'connection_manager.dart';
part 'connection_manager_imp.dart';

const _sensitiveRequestHeaders = {
  'authorization',
  'proxy-authorization',
  'cookie',
};

/// A Dio HttpAdapter which implements Http/2.0.
class Http2Adapter extends HttpClientAdapter {
  final ConnectionManager _connectionMgr;
  late final DefaultHttpClientAdapter _http1Adapter = DefaultHttpClientAdapter()..onHttpClientCreate = _onHttp1ClientCreate;

  Http2Adapter(ConnectionManager? connectionManager)
      : _connectionMgr = connectionManager ?? ConnectionManager();
  
  HttpClient? _onHttp1ClientCreate(HttpClient client) {
    client.connectionFactory = _connectionMgr.connectionFactory;
    return client;
  }

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  ) {
    return fetchFollowingRedirects(
      fetchOne: _fetchSingle,
      options: options,
      requestStream: requestStream,
      cancelFuture: cancelFuture,
    );
  }

  Future<ResponseBody> _fetchSingle(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  ) async {
    final transport = await _connectionMgr.getConnection(options);
    if (transport == null) {
      // HTTP 1.x
      return _http1Adapter.fetch(options, requestStream, cancelFuture);
    }
    final uri = options.uri;
    var path = uri.path;

    if (path.isEmpty || !path.startsWith('/')) path = '/' + path;
    if (uri.query.trim().isNotEmpty) path += ('?' + uri.query);
    var headers = [
      Header.ascii(':method', options.method),
      if (!Platform.isAndroid) Header.ascii(':scheme', uri.scheme),
      Header.ascii(':authority', uri.host),
      if (Platform.isAndroid) Header.ascii(':scheme', uri.scheme),
      Header.ascii(':path', path),
    ];

    // Add custom headers
    headers.addAll(
      options.headers.keys.map((key) {
        final normalizedName = key.toLowerCase();
        return Header.ascii(
          normalizedName,
          options.headers[key]?.toString() ?? '',
          neverIndexed: _sensitiveRequestHeaders.contains(normalizedName),
        );
      }),
    );

    var hasRequestData = requestStream != null;

    // Creates a new outgoing stream.
    final stream = transport.makeRequest(headers, endStream: !hasRequestData);

    // ignore: unawaited_futures
    cancelFuture?.whenComplete(() {
      Future(() {
        stream.terminate();
      });
    });

    if (hasRequestData) {
      await requestStream!.listen((data) {
        stream.outgoingMessages.add(DataStreamMessage(data));
      }).asFuture();
    }

    await stream.outgoingMessages.close();

    final sc = StreamController<Uint8List>(sync: true);
    final responseHeaders = Headers();
    var completer = Completer();
    late int statusCode;
    late StreamSubscription subscription;
    var needResponse = false;
    var responseFinished = false;
    subscription = stream.incomingMessages.listen(
      (message) async {
        if (message is HeadersStreamMessage) {
          for (var header in message.headers) {
            var name = utf8.decode(header.name);
            var value = utf8.decode(header.value);
            responseHeaders.add(name, value);
          }

          var status = responseHeaders.value(':status');
          if (status != null) {
            statusCode = int.parse(status);
            responseHeaders.removeAll(':status');

            needResponse = options.validateStatus(statusCode) ||
                options.receiveDataWhenStatusError;

            completer.complete();
          }
        } else if (message is DataStreamMessage) {
          if (needResponse) {
            sc.add(Uint8List.fromList(message.bytes));
          } else {
            // ignore: unawaited_futures
            subscription.cancel().whenComplete(() => sc.close());
          }
        }
      },
      onDone: () {
        responseFinished = true;
        sc.close();
      },
      onError: (e) {
        responseFinished = true;
        // If connection is being forcefully terminated, remove the connection
        if (e is TransportConnectionException) {
          _connectionMgr.removeConnection(transport);
        }
        if (!completer.isCompleted) {
          completer.completeError(e, StackTrace.current);
        } else {
          sc.addError(e);
        }
      },
      cancelOnError: true,
    );
    sc.onCancel = () {
      if (!responseFinished) stream.terminate();
      return subscription.cancel();
    };

    await completer.future;

    final isGzip = responseHeaders.value(HttpHeaders.contentEncodingHeader) == 'gzip';
    return ResponseBody(
      isGzip ? gzip.decoder.bind(sc.stream).cast<Uint8List>() : sc.stream,
      statusCode,
      headers: responseHeaders.map,
    );
  }

  @override
  void close({bool force = false}) {
    _connectionMgr.close(force: force);
  }
}
