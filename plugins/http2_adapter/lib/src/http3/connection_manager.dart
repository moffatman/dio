part of '../http3_adapter.dart';

class QuicTlsClientConfig {
  QuicTlsClientConfig({
    required this.host,
    required this.port,
    required this.securityContext,
    required this.onBadCertificate,
    required this.transportParameters,
    this.applicationProtocols = const <String>['h3'],
  });

  final String host;
  final int port;
  final SecurityContext? securityContext;
  final bool Function(X509Certificate certificate)? onBadCertificate;
  final QuicTransportParameters transportParameters;
  final List<String> applicationProtocols;
}

/// A TLS driver session that produces protected QUIC datagrams.
///
/// The adapter keeps UDP socket ownership here, while the driver owns the TLS
/// state machine and packet protection that dart:io currently does not expose.
abstract class QuicTlsClientSession {
  bool get isHandshakeComplete;

  String? get selectedProtocol;

  Future<QuicClientStream> openBidirectionalStream();

  Future<Iterable<Uint8List>> takeOutgoingDatagrams();

  Future<void> handleIncomingDatagram(Uint8List datagram);

  Future<void> close();
}

abstract class QuicClientStream {
  Stream<Uint8List> get incoming;

  void add(List<int> bytes);

  Future<void> close();

  void terminate();
}

class Http3HandshakeUnavailableException implements IOException {
  Http3HandshakeUnavailableException(this.message);

  final String message;

  @override
  String toString() => 'Http3HandshakeUnavailableException: $message';
}

class Http3RequestRejectedException implements Exception {
  const Http3RequestRejectedException({
    required this.streamId,
    required this.goawayId,
  });

  final int streamId;
  final int goawayId;

  @override
  String toString() => 'HTTP/3 request stream $streamId was rejected by '
      'GOAWAY $goawayId';
}

class Http3RequestCancelledException implements Exception {
  const Http3RequestCancelledException(this.streamId);

  final int streamId;

  @override
  String toString() => 'HTTP/3 request stream $streamId was cancelled';
}

abstract class Http3ConnectionManager {
  Http3ConnectionManager._();

  factory Http3ConnectionManager({
    int idleTimeout = 15000,
    void Function(Uri uri, ClientSetting)? onClientCreate,
    ConnectionManager? tcpConnectionManager,
    bool preferHttp3WithoutAltSvc = false,
    Duration http3FailureCooldown = const Duration(minutes: 5),
    Duration http3ConnectTimeout = const Duration(seconds: 15),
    bool useNativeUdp = false,
  }) {
    return _DatagramHttp3ConnectionManager(
      idleTimeout: idleTimeout,
      onClientCreate: onClientCreate,
      tcpConnectionManager: tcpConnectionManager,
      preferHttp3WithoutAltSvc: preferHttp3WithoutAltSvc,
      http3FailureCooldown: http3FailureCooldown,
      http3ConnectTimeout: http3ConnectTimeout,
      useNativeUdp: useNativeUdp,
    );
  }

  Http2Adapter get _tcpAdapter;

  bool shouldAttemptHttp3(RequestOptions options);

  Future<Http3ClientConnection?> getConnection(RequestOptions options);

  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture, {
    bool allowFallback = true,
  }) async {
    if (!shouldAttemptHttp3(options)) {
      if (!allowFallback) {
        throw Http3HandshakeUnavailableException(
          'HTTP/3 is not available for ${options.uri.origin}.',
        );
      }
      return _fetchTcp(options, requestStream, cancelFuture);
    }

    late final Http3ClientConnection? connection;
    try {
      connection = await _getConnectionWithIdleTimeoutRetry(options);
    } on Object catch (error, stackTrace) {
      if (!_isHttp3Unavailable(error) || !allowFallback) {
        Error.throwWithStackTrace(error, stackTrace);
      }
      if (!_isQuicIdleTimeout(error)) {
        markHttp3Unavailable(options.uri);
      }
      return _fetchTcp(options, requestStream, cancelFuture);
    }
    if (connection == null) {
      if (!allowFallback) {
        throw Http3HandshakeUnavailableException(
          'HTTP/3 is not available for ${options.uri.origin}.',
        );
      }
      return _fetchTcp(options, requestStream, cancelFuture);
    }

    try {
      final response =
          await connection.fetch(options, requestStream, cancelFuture);
      recordResponseHeaders(options.uri, response.headers);
      return response;
    } on Object catch (error, stackTrace) {
      if (error is Http3RequestRejectedException && requestStream == null) {
        return _retryWithFreshHttp3Connection(
          options,
          cancelFuture,
          allowFallback: allowFallback,
          originalError: error,
          originalStackTrace: stackTrace,
        );
      }
      if (_isQuicIdleTimeout(error)) {
        removeConnection(connection);
        if (requestStream == null && _isReplaySafeHttpMethod(options.method)) {
          return _retryWithFreshHttp3Connection(
            options,
            cancelFuture,
            allowFallback: allowFallback,
            originalError: error,
            originalStackTrace: stackTrace,
          );
        }
        Error.throwWithStackTrace(error, stackTrace);
      }
      if (error is Http3ConnectionTerminatedException) {
        rethrow;
      }
      // TODO: Improve
      if (!_isHttp3Unavailable(error) ||
          !allowFallback ||
          requestStream != null ||
          !_isReplaySafeHttpMethod(options.method)) {
        Error.throwWithStackTrace(error, stackTrace);
      }
      markHttp3Unavailable(options.uri);
      return _fetchTcp(options, requestStream, cancelFuture);
    }
  }

  Future<Http3ClientConnection?> _getConnectionWithIdleTimeoutRetry(
    RequestOptions options,
  ) async {
    try {
      return await getConnection(options);
    } on Object catch (error, stackTrace) {
      if (!_isQuicIdleTimeout(error)) {
        Error.throwWithStackTrace(error, stackTrace);
      }
      return getConnection(options);
    }
  }

  Future<ResponseBody> _retryWithFreshHttp3Connection(
    RequestOptions options,
    Future? cancelFuture, {
    required bool allowFallback,
    required Object originalError,
    required StackTrace originalStackTrace,
  }) async {
    Http3ClientConnection? replacement;
    try {
      replacement = await getConnection(options);
      if (replacement == null) {
        if (!allowFallback) {
          Error.throwWithStackTrace(originalError, originalStackTrace);
        }
        return _fetchTcp(options, null, cancelFuture);
      }
      final response = await replacement.fetch(options, null, cancelFuture);
      recordResponseHeaders(options.uri, response.headers);
      return response;
    } on Object catch (error, stackTrace) {
      if (_isQuicIdleTimeout(error)) {
        if (replacement != null) {
          removeConnection(replacement);
        }
        if (!allowFallback) {
          Error.throwWithStackTrace(error, stackTrace);
        }
        return _fetchTcp(options, null, cancelFuture);
      }
      if (!_isHttp3Unavailable(error) || !allowFallback) {
        Error.throwWithStackTrace(error, stackTrace);
      }
      markHttp3Unavailable(options.uri);
      return _fetchTcp(options, null, cancelFuture);
    }
  }

  bool _isQuicIdleTimeout(Object error) {
    final termination = switch (error) {
      QuicConnectionException() => error.termination,
      Http3ConnectionTerminatedException() => error.termination,
      _ => null,
    };
    return termination?.type == QuicConnectionTerminationType.idleTimeout;
  }

  Future<ResponseBody> _fetchTcp(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  ) async {
    final response = await _tcpAdapter.fetch(
      options,
      requestStream,
      cancelFuture,
    );
    recordResponseHeaders(options.uri, response.headers);
    return response;
  }

  bool _isHttp3Unavailable(Object error) {
    return error is Http3HandshakeUnavailableException ||
        error is HandshakeException ||
        error is SocketException ||
        error is TimeoutException ||
        error is QuicConnectionException ||
        error is Http3ConnectionTerminatedException;
  }

  void recordResponseHeaders(Uri uri, Map<String, List<String>> headers);

  void markHttp3Unavailable(Uri uri);

  void removeConnection(Http3ClientConnection transport);

  void close({bool force = false});
}

abstract class Http3ClientConnection {
  String get host;

  bool get isOpen;

  bool get canAcceptRequests;

  InternetAddress get remoteAddress;

  int get remotePort;

  bool get isHandshakeComplete;

  bool get isEarlyData;

  bool? get earlyDataAccepted;

  Future<bool> get handshakeComplete;

  void Function(bool) get onActiveStateChanged;

  set onActiveStateChanged(void Function(bool) callback);

  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  );

  Future<void> finish();

  Future<void> migrate({
    RawDatagramSocket? socket,
    InternetAddress? remoteAddress,
    int? remotePort,
  });
}
