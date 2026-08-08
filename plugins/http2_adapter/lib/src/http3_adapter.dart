import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:dio/dio.dart';

import 'http2_adapter.dart';
import 'redirect.dart';

part 'http3/connection_manager.dart';
part 'http3/connection_manager_imp.dart';
part 'http3/datagram_connection_manager.dart';
part 'http3/http3.dart';
part 'http3/huffman.dart';
part 'http3/qpack.dart';
part 'http3/quic.dart';

/// A Dio adapter that prefers HTTP/3 over QUIC and falls back to the existing
/// HTTP/2/HTTP/1 adapter when QUIC cannot be negotiated.
class Http3Adapter extends HttpClientAdapter {
  Http3Adapter(
    Http3ConnectionManager? connectionManager, {
    this.allowFallback = true,
    ConnectionManager? tcpConnectionManager,
  }) {
    _connectionMgr = connectionManager ??
        Http3ConnectionManager(
          tcpConnectionManager: tcpConnectionManager,
        );
  }

  late final Http3ConnectionManager _connectionMgr;

  /// Whether to use the existing HTTP/2/HTTP/1 adapter when HTTP/3 is not
  /// available for the target request.
  final bool allowFallback;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  ) {
    return fetchFollowingRedirects(
      fetchOne: (options, requestStream, cancelFuture) {
        return _connectionMgr.fetch(
          options,
          requestStream,
          cancelFuture,
          allowFallback: allowFallback,
        );
      },
      options: options,
      requestStream: requestStream,
      cancelFuture: cancelFuture,
    );
  }

  @override
  void close({bool force = false}) {
    _connectionMgr.close(force: force);
  }
}
