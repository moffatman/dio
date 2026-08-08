part of '../http3_adapter.dart';

class Http3ConnectionTerminatedException implements Exception {
  const Http3ConnectionTerminatedException(this.termination);

  final QuicConnectionTermination termination;

  @override
  String toString() => 'HTTP/3 connection terminated: '
      '${termination.type.name}, error ${termination.errorCode}'
      '${termination.frameType == null ? '' : ', frame ${termination.frameType}'}'
      '${termination.reason.isEmpty ? '' : ': ${termination.reason}'}';
}

bool _isReplaySafeHttpMethod(String method) {
  return switch (method.toUpperCase()) {
    'GET' || 'HEAD' || 'OPTIONS' || 'TRACE' => true,
    _ => false,
  };
}

/// HTTP/3 connection manager backed by dart:io's QUIC datagram socket.
class _DatagramHttp3ConnectionManager extends Http3ConnectionManager {
  _DatagramHttp3ConnectionManager({
    int idleTimeout = 15000,
    this.onClientCreate,
    ConnectionManager? tcpConnectionManager,
    this.preferHttp3WithoutAltSvc = false,
    this.http3FailureCooldown = const Duration(minutes: 5),
    this.http3ConnectTimeout = const Duration(seconds: 15),
    this.useNativeUdp = false,
  })  : _idleTimeout = idleTimeout,
        _ownsTcpConnectionManager = tcpConnectionManager == null,
        _tcpConnectionManager = tcpConnectionManager ??
            ConnectionManager(
              idleTimeout: idleTimeout,
              onClientCreate: onClientCreate,
            ),
        super._();

  final void Function(Uri uri, ClientSetting)? onClientCreate;
  final ConnectionManager _tcpConnectionManager;
  final bool _ownsTcpConnectionManager;

  @override
  late final Http2Adapter _tcpAdapter = Http2Adapter(_tcpConnectionManager);
  final bool preferHttp3WithoutAltSvc;
  final Duration http3FailureCooldown;
  final Duration http3ConnectTimeout;
  final bool useNativeUdp;
  final int _idleTimeout;

  final _connections = <String, _DatagramHttp3ConnectionState>{};
  final _connectFutures = <String, Future<_DatagramHttp3ConnectionState>>{};
  final _advertisedHttp3Origins = <String, _Http3AlternativeService>{};
  final _failedHttp3Origins = <String, _FailedHttp3AlternativeService>{};
  final _newTokens = <String, _DatagramHttp3CachedToken>{};
  final _resumptionStates = <String, _DatagramHttp3CachedResumptionState>{};

  bool _closed = false;
  bool _forceClosed = false;

  @override
  bool shouldAttemptHttp3(RequestOptions options) {
    return _http3AlternativeFor(options) != null;
  }

  @override
  Future<Http3ClientConnection?> getConnection(
    RequestOptions options,
  ) async {
    if (_closed) {
      throw Exception(
        "Can't establish connection after "
        '[Http3ConnectionManager] closed!',
      );
    }
    final alternative = _http3AlternativeFor(options);
    if (alternative == null) return null;

    final origin = _originKey(options.uri);
    var state = _connections[origin];
    if (state == null ||
        !state.connection.isOpen ||
        !state.connection.canAcceptRequests) {
      state?.dispose();
      final existingConnect = _connectFutures[origin];
      final initFuture = existingConnect ??
          (_connectFutures[origin] = _connect(options, alternative));
      try {
        state = await initFuture;
        if (_forceClosed) {
          await state.dispose();
        } else {
          _connections[origin] = state;
        }
      } finally {
        if (_connectFutures[origin] == initFuture) {
          _connectFutures.remove(origin);
        }
      }
    }
    return state.activeConnection;
  }

  Future<_DatagramHttp3ConnectionState> _connect(
    RequestOptions options,
    _Http3AlternativeService alternative,
  ) async {
    final uri = options.uri;
    final origin = _originKey(uri);
    final cachedToken = _newTokens.remove(origin);
    final initialToken = cachedToken != null &&
            cachedToken.host == alternative.host &&
            cachedToken.port == alternative.port
        ? cachedToken.token
        : null;
    final allowEarlyData = _isReplaySafeHttpMethod(options.method);
    final cachedResumption =
        allowEarlyData ? _resumptionStates.remove(origin) : null;
    final resumptionState = cachedResumption != null &&
            cachedResumption.host == alternative.host &&
            cachedResumption.port == alternative.port
        ? cachedResumption.state
        : null;
    final clientConfig = ClientSetting();
    onClientCreate?.call(uri, clientConfig);

    final timeout = options.connectTimeout > 0
        ? Duration(milliseconds: options.connectTimeout)
        : http3ConnectTimeout;
    late final RawDatagramSecureSocket socket;
    try {
      socket = await RawDatagramSecureSocket.connect(
        alternative.host,
        alternative.port,
        context: clientConfig.context,
        onBadCertificate: clientConfig.onBadCertificate,
        supportedProtocols: const <String>['h3'],
        protocolSettings: (clientConfig.useAlps ?? Platform.isAndroid)
            ? {'h3': Uint8List(0)}
            : {},
        useEchGrease: clientConfig.useEchGrease,
        initialToken: initialToken,
        resumptionState: resumptionState,
        enableEarlyData: allowEarlyData && resumptionState != null,
        useNativeUdp: useNativeUdp,
        timeout: timeout,
      );
    } on Object catch (error, stackTrace) {
      if (_isHttp3Unavailable(error)) {
        _markHttp3AlternativeUnavailable(origin, alternative);
      }
      Error.throwWithStackTrace(error, stackTrace);
    }
    final transport = _DatagramQuicTransport(
      socket,
      onNewToken: (token) {
        if (token.length > 1024) return;
        _newTokens.remove(origin);
        _newTokens[origin] = _DatagramHttp3CachedToken(
          host: alternative.host,
          port: alternative.port,
          token: Uint8List.fromList(token),
        );
        if (_newTokens.length > 64) {
          _newTokens.remove(_newTokens.keys.first);
        }
      },
      onResumptionState: (resumptionState) {
        _resumptionStates.remove(origin);
        _resumptionStates[origin] = _DatagramHttp3CachedResumptionState(
          host: alternative.host,
          port: alternative.port,
          state: Uint8List.fromList(resumptionState),
        );
        if (_resumptionStates.length > 64) {
          _resumptionStates.remove(_resumptionStates.keys.first);
        }
      },
    );
    if (socket.isHandshakeComplete) {
      await _tryPreferredAddress(socket);
    } else {
      unawaited(_tryPreferredAddressAfterHandshake(socket));
    }

    final connection = _DatagramHttp3ClientConnection(
      transport: transport,
      host: uri.host,
    );

    final state = _DatagramHttp3ConnectionState(connection);
    transport.onGoaway = (_) {
      if (identical(_connections[origin], state)) {
        _connections.remove(origin);
      }
    };
    transport.onDrained = () {
      if (identical(_connections[origin], state)) {
        _connections.remove(origin);
      }
      unawaited(state.dispose());
    };
    connection.onActiveStateChanged = (isActive) {
      state.isActive = isActive;
      if (!isActive) {
        state.latestIdleTimeStamp = DateTime.now().millisecondsSinceEpoch;
      }
    };
    state.delayClose(_closed ? 50 : _idleTimeout, () {
      _connections.remove(_originKey(uri));
      state.connection.finish();
    });
    return state;
  }

  Future<void> _tryPreferredAddress(RawDatagramSecureSocket socket) async {
    final preferred = socket.peerPreferredAddress;
    if (preferred == null) return;

    InternetAddress? address;
    int? port;
    if (socket.address.type == InternetAddressType.IPv4) {
      address = preferred.ipv4Address;
      port = preferred.ipv4Port;
    } else if (socket.address.type == InternetAddressType.IPv6) {
      address = preferred.ipv6Address;
      port = preferred.ipv6Port;
    }
    if (address == null || port == null) return;

    try {
      await socket.migrate(remoteAddress: address, remotePort: port);
    } on SocketException {
      // The original path remains active when the preferred path is unusable.
    } on TimeoutException {
      // The original path remains active when path validation times out.
    }
  }

  Future<void> _tryPreferredAddressAfterHandshake(
    RawDatagramSecureSocket socket,
  ) async {
    try {
      await socket.handshakeComplete;
      await _tryPreferredAddress(socket);
    } on Object {
      // Connection errors are surfaced by the HTTP/3 transport.
    }
  }

  @override
  void recordResponseHeaders(Uri uri, Map<String, List<String>> headers) {
    if (!uri.isScheme('https')) return;
    final altSvcValues = <String>[];
    headers.forEach((name, values) {
      if (name.toLowerCase() == 'alt-svc') {
        altSvcValues.addAll(values);
      }
    });
    if (altSvcValues.isEmpty) return;

    final origin = _originKey(uri);
    for (final value in altSvcValues) {
      for (final entry in _splitAltSvcHeader(value)) {
        final alternative = _parseAltSvcEntry(uri, entry);
        if (alternative == _Http3AlternativeService.clear) {
          _advertisedHttp3Origins.remove(origin);
          _failedHttp3Origins.remove(origin);
          _newTokens.remove(origin);
          _resumptionStates.remove(origin);
          continue;
        }
        if (alternative != null) {
          _advertisedHttp3Origins[origin] = alternative;
        }
      }
    }
  }

  @override
  void markHttp3Unavailable(Uri uri) {
    final origin = _originKey(uri);
    final alternative = _advertisedHttp3Origins[origin];
    _markHttp3AlternativeUnavailable(
      origin,
      alternative ??
          _Http3AlternativeService(
            host: uri.host,
            port: uri.port,
            expiresAt: DateTime.now(),
          ),
    );
  }

  void _markHttp3AlternativeUnavailable(
    String origin,
    _Http3AlternativeService alternative,
  ) {
    _failedHttp3Origins[origin] = _FailedHttp3AlternativeService(
      host: alternative.host,
      port: alternative.port,
      retryAfter: DateTime.now().add(http3FailureCooldown),
    );
    _newTokens.remove(origin);
    _resumptionStates.remove(origin);
    final state = _connections.remove(origin);
    state?.dispose();
  }

  @override
  void removeConnection(Http3ClientConnection connection) {
    _DatagramHttp3ConnectionState? removed;
    _connections.removeWhere((_, state) {
      if (state.connection == connection) {
        removed = state;
        return true;
      }
      return false;
    });
    removed?.dispose();
  }

  Future<void> migrateConnection(
    Uri uri, {
    RawDatagramSocket? socket,
    InternetAddress? remoteAddress,
    int? remotePort,
  }) {
    final state = _connections[_originKey(uri)];
    if (state == null || !state.connection.isOpen) {
      return Future<void>.error(
        StateError('There is no active HTTP/3 connection for $uri.'),
      );
    }
    return state.connection.migrate(
      socket: socket,
      remoteAddress: remoteAddress,
      remotePort: remotePort,
    );
  }

  @override
  void close({bool force = false}) {
    _closed = true;
    _forceClosed = force;
    if (_ownsTcpConnectionManager) {
      _tcpConnectionManager.close(force: force);
    }
    if (force) {
      _connections.forEach((_, state) => state.dispose());
    }
  }

  _Http3AlternativeService? _http3AlternativeFor(RequestOptions options) {
    if (!options.uri.isScheme('https')) return null;
    if (options.preferHttp3WithoutAltSvc == false) return null;
    final origin = _originKey(options.uri);
    final now = DateTime.now();

    var alternative = _advertisedHttp3Origins[origin];
    if (alternative != null) {
      if (!alternative.expiresAt.isAfter(now)) {
        _advertisedHttp3Origins.remove(origin);
        alternative = null;
      }
    }

    if (alternative == null &&
        (preferHttp3WithoutAltSvc ||
            options.preferHttp3WithoutAltSvc == true)) {
      alternative = _Http3AlternativeService(
        host: options.uri.host,
        port: options.uri.port,
        expiresAt: now.add(const Duration(minutes: 1)),
      );
    }
    if (alternative == null) return null;

    final failed = _failedHttp3Origins[origin];
    if (failed != null) {
      if (!failed.retryAfter.isAfter(now)) {
        _failedHttp3Origins.remove(origin);
      } else if (failed.matches(alternative)) {
        return null;
      }
    }
    return alternative;
  }

  String _originKey(Uri uri) => '${uri.scheme}://${uri.host}:${uri.port}';

  List<String> _splitAltSvcHeader(String header) {
    final entries = <String>[];
    final current = StringBuffer();
    var inQuotes = false;
    for (var i = 0; i < header.length; i++) {
      final char = header[i];
      if (char == '"') {
        inQuotes = !inQuotes;
      }
      if (char == ',' && !inQuotes) {
        entries.add(current.toString().trim());
        current.clear();
      } else {
        current.write(char);
      }
    }
    final last = current.toString().trim();
    if (last.isNotEmpty) entries.add(last);
    return entries;
  }

  List<String> _splitAltSvcParameters(String entry) {
    final parts = <String>[];
    final current = StringBuffer();
    var inQuotes = false;
    for (var i = 0; i < entry.length; i++) {
      final char = entry[i];
      if (char == '"') {
        inQuotes = !inQuotes;
      }
      if (char == ';' && !inQuotes) {
        parts.add(current.toString().trim());
        current.clear();
      } else {
        current.write(char);
      }
    }
    final last = current.toString().trim();
    if (last.isNotEmpty) parts.add(last);
    return parts;
  }

  _Http3AlternativeService? _parseAltSvcEntry(Uri uri, String entry) {
    if (entry.toLowerCase() == 'clear') {
      return _Http3AlternativeService.clear;
    }
    final parts = _splitAltSvcParameters(entry);
    if (parts.isEmpty) return null;
    final first = parts.first;
    final equalsIndex = first.indexOf('=');
    if (equalsIndex <= 0) return null;
    final protocol = first.substring(0, equalsIndex).trim().toLowerCase();
    if (protocol != 'h3' && !protocol.startsWith('h3-')) return null;

    final authority = _unquote(first.substring(equalsIndex + 1).trim());
    final parsedAuthority = _parseAltAuthority(uri, authority);
    if (parsedAuthority == null) return null;

    var maxAge = const Duration(seconds: 86400);
    for (final parameter in parts.skip(1)) {
      final parameterEquals = parameter.indexOf('=');
      if (parameterEquals <= 0) continue;
      final name = parameter.substring(0, parameterEquals).trim().toLowerCase();
      if (name != 'ma') continue;
      final value = int.tryParse(_unquote(
        parameter.substring(parameterEquals + 1).trim(),
      ));
      if (value != null) {
        maxAge = Duration(seconds: value);
      }
    }

    return _Http3AlternativeService(
      host: parsedAuthority.host,
      port: parsedAuthority.port,
      expiresAt: DateTime.now().add(maxAge),
    );
  }

  _Http3AlternativeService? _parseAltAuthority(Uri uri, String authority) {
    if (authority.isEmpty) return null;
    if (authority.startsWith(':')) {
      final port = int.tryParse(authority.substring(1));
      if (port == null) return null;
      return _Http3AlternativeService(
        host: uri.host,
        port: port,
        expiresAt: DateTime.now(),
      );
    }
    final parsed = Uri.tryParse('https://$authority');
    if (parsed == null || parsed.host.isEmpty) return null;
    return _Http3AlternativeService(
      host: parsed.host,
      port: parsed.hasPort ? parsed.port : uri.port,
      expiresAt: DateTime.now(),
    );
  }

  String _unquote(String value) {
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      return value.substring(1, value.length - 1);
    }
    return value;
  }
}

class _DatagramHttp3CachedToken {
  const _DatagramHttp3CachedToken({
    required this.host,
    required this.port,
    required this.token,
  });

  final String host;
  final int port;
  final Uint8List token;
}

class _DatagramHttp3CachedResumptionState {
  const _DatagramHttp3CachedResumptionState({
    required this.host,
    required this.port,
    required this.state,
  });

  final String host;
  final int port;
  final Uint8List state;
}

class _DatagramHttp3ClientConnection implements Http3ClientConnection {
  _DatagramHttp3ClientConnection({
    required _DatagramQuicTransport transport,
    required this.host,
  }) : _transport = transport;

  final _DatagramQuicTransport _transport;
  @override
  final String host;

  @override
  void Function(bool) onActiveStateChanged = (_) {};

  bool _closed = false;
  int _activeRequestCount = 0;

  void _requestStarted() {
    if (_activeRequestCount++ == 0) {
      onActiveStateChanged(true);
    }
  }

  void _requestFinished() {
    if (_activeRequestCount == 0) return;
    if (--_activeRequestCount == 0) {
      onActiveStateChanged(false);
    }
  }

  @override
  bool get isOpen => !_closed;

  @override
  bool get canAcceptRequests => !_closed && _transport.canAcceptRequests;

  @override
  InternetAddress get remoteAddress => _transport.remoteAddress;

  @override
  int get remotePort => _transport.remotePort;

  @override
  bool get isHandshakeComplete => _transport.isHandshakeComplete;

  @override
  bool get isEarlyData => _transport.isEarlyData;

  @override
  bool? get earlyDataAccepted => _transport.earlyDataAccepted;

  @override
  Future<bool> get handshakeComplete => _transport.handshakeComplete;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future? cancelFuture,
  ) async {
    _requestStarted();
    var requestFinished = false;
    void finishRequest() {
      if (requestFinished) return;
      requestFinished = true;
      _requestFinished();
    }

    try {
      if (_transport.isEarlyData && !_isReplaySafeHttpMethod(options.method)) {
        await _transport.handshakeComplete;
      }
      if (_transport.selectedProtocol != 'h3') {
        throw Http3HandshakeUnavailableException(
          'HTTP/3 requires a completed QUIC TLS handshake with ALPN h3.',
        );
      }

      final stream = await _transport.openBidirectionalStream();
      final responseData = StreamController<Uint8List>(sync: true);
      final responseHeaders = Headers();
      final frameDecoder = Http3FrameDecoder(streamDataFrames: true);
      final responseReady = Completer<void>();
      final cancellationSignal = Completer<void>();
      var headerDecoding = Future<void>.value();
      var requestCancelled = false;
      late int statusCode;

      late final StreamSubscription<Uint8List> subscription;
      subscription = stream.incoming.listen(
        (data) {
          for (final frame in frameDecoder.add(data)) {
            if (frame is Http3HeadersFrame) {
              headerDecoding = headerDecoding.then((_) async {
                final headers = await _transport.decodeResponseHeaders(
                  stream.id,
                  frame.headerBlock,
                );
                headers.forEach(responseHeaders.add);
                final status = responseHeaders.value(':status');
                if (status != null && !responseReady.isCompleted) {
                  statusCode = int.parse(status);
                  responseHeaders.removeAll(':status');
                  responseReady.complete();
                }
              });
              unawaited(
                  headerDecoding.catchError((Object error, StackTrace st) {
                if (!responseReady.isCompleted) {
                  responseReady.completeError(error, st);
                } else {
                  responseData.addError(error, st);
                }
              }));
            } else if (frame is Http3DataFrame) {
              responseData.add(frame.data);
            }
          }
        },
        onDone: () {
          unawaited(headerDecoding.then((_) {
            if (!responseReady.isCompleted) {
              responseReady.completeError(
                const FormatException('HTTP/3 response ended before headers'),
              );
            }
            responseData.close();
            finishRequest();
          }, onError: (Object error, StackTrace stackTrace) {
            if (!responseReady.isCompleted) {
              responseReady.completeError(error, stackTrace);
            }
            responseData.close();
            finishRequest();
          }));
        },
        onError: (Object error, StackTrace stackTrace) {
          _transport.cancelResponseHeaders(stream.id);
          if (!responseReady.isCompleted) {
            responseReady.completeError(error, stackTrace);
          } else {
            responseData.addError(error, stackTrace);
          }
          unawaited(responseData.close());
          finishRequest();
        },
        cancelOnError: true,
      );
      // A response-side failure can arrive while fetch is still sending the
      // request body. Observe it now so it is not reported as unhandled before
      // the await below rethrows it to the caller.
      unawaited(responseReady.future.then<void>(
        (_) {},
        onError: (Object _, StackTrace __) {},
      ));

      StreamSubscription<Uint8List>? requestSubscription;
      void cancelRequest() {
        if (requestCancelled) return;
        requestCancelled = true;
        final error = Http3RequestCancelledException(stream.id);
        _transport.cancelRequest(stream.id, error, StackTrace.current);
        if (!cancellationSignal.isCompleted) {
          cancellationSignal.complete();
        }
        unawaited(requestSubscription?.cancel());
      }

      if (cancelFuture != null) {
        unawaited(cancelFuture.then<void>(
          (_) => cancelRequest(),
          onError: (Object _, StackTrace __) => cancelRequest(),
        ));
      }

      stream.add(_transport.encodeRequestHeaders(stream.id, options));
      if (requestStream != null) {
        final requestDone = Completer<void>();
        requestSubscription = requestStream.listen(
          (data) => stream.add(Http3DataFrame(data).encode()),
          onError: requestDone.completeError,
          onDone: requestDone.complete,
        );
        await Future.any<void>([
          requestDone.future,
          cancellationSignal.future,
        ]);
      }
      if (!requestCancelled) {
        await stream.close();
      }

      await responseReady.future;
      responseData.onCancel = () {
        _transport.cancelRequest(stream.id);
        finishRequest();
        return subscription.cancel();
      };
      final isGzip =
          responseHeaders.value(HttpHeaders.contentEncodingHeader) == 'gzip';
      return ResponseBody(
        isGzip
            ? gzip.decoder.bind(responseData.stream).cast<Uint8List>()
            : responseData.stream,
        statusCode,
        headers: responseHeaders.map,
      );
    } catch (_) {
      finishRequest();
      rethrow;
    }
  }

  @override
  Future<void> finish() async {
    if (_closed) return;
    _closed = true;
    await _transport.close();
  }

  @override
  Future<void> migrate({
    RawDatagramSocket? socket,
    InternetAddress? remoteAddress,
    int? remotePort,
  }) {
    if (_closed) {
      return Future<void>.error(StateError('HTTP/3 connection is closed.'));
    }
    return _transport.migrate(
      socket: socket,
      remoteAddress: remoteAddress,
      remotePort: remotePort,
    );
  }
}

class _DatagramQuicTransport {
  _DatagramQuicTransport(
    this._socket, {
    this.onNewToken,
    this.onResumptionState,
  }) {
    _qpackDecoder = QpackDecoder(
      maximumTableCapacity: _qpackMaximumTableCapacity,
      maximumBlockedStreams: _qpackMaximumBlockedStreams,
      onDecoderInstructions: _queueQpackDecoderInstructions,
    );
    _qpackEncoder = QpackEncoder(
      preferredTableCapacity: _qpackMaximumTableCapacity,
      onEncoderInstructions: _queueQpackEncoderInstructions,
    );
    _subscription = _socket.listen(
      _handleSocketEvent,
      onError: _handleSocketError,
      onDone: () => _closeAll(),
    );
  }

  final RawDatagramSecureSocket _socket;
  final void Function(Uint8List token)? onNewToken;
  final void Function(Uint8List state)? onResumptionState;
  void Function(int id)? onGoaway;
  void Function()? onDrained;
  final _streams = <int, _DatagramQuicStream>{};
  final _peerStreams = <int, _DatagramPeerStream>{};
  final _pendingWrites = <int, Queue<_DatagramPendingWrite>>{};
  late final QpackDecoder _qpackDecoder;
  late final QpackEncoder _qpackEncoder;
  late final StreamSubscription<RawSocketEvent> _subscription;

  static const int _qpackMaximumTableCapacity = 16383; // From WebKit
  static const int _qpackMaximumBlockedStreams = 100; // From WebKit

  var _sentControlStream = false;
  int? _controlStreamId;
  Future<void>? _controlStreamFuture;
  int? _qpackEncoderStreamId;
  int? _qpackDecoderStreamId;
  Future<void>? _qpackEncoderStreamFuture;
  Future<void>? _qpackDecoderStreamFuture;
  final _pendingQpackEncoderInstructions = Queue<Uint8List>();
  final _pendingQpackDecoderInstructions = Queue<Uint8List>();
  final _peerCriticalStreams = <int, int>{};
  Completer<void>? _streamCapacityChanged;
  var _closed = false;
  var _flushingWrites = false;
  var _drainedNotified = false;
  int? _peerGoawayId;
  Object? _terminalError;
  StackTrace? _terminalStackTrace;

  String? get selectedProtocol => _socket.selectedProtocol;

  InternetAddress get remoteAddress => _socket.remoteAddress;

  int get remotePort => _socket.remotePort;

  bool get isHandshakeComplete => _socket.isHandshakeComplete;

  bool get isEarlyData => _socket.isEarlyData;

  bool? get earlyDataAccepted => _socket.earlyDataAccepted;

  Future<bool> get handshakeComplete => _socket.handshakeComplete;

  bool get canAcceptRequests => !_closed && _peerGoawayId == null;

  Future<void> migrate({
    RawDatagramSocket? socket,
    InternetAddress? remoteAddress,
    int? remotePort,
  }) {
    if (_closed) {
      return Future<void>.error(
        _terminalError ?? StateError('HTTP/3 connection is closed'),
      );
    }
    return _socket.migrate(
      socket: socket,
      remoteAddress: remoteAddress,
      remotePort: remotePort,
    );
  }

  Future<_DatagramQuicStream> openBidirectionalStream() async {
    if (_closed) {
      Error.throwWithStackTrace(
        _terminalError ?? StateError('HTTP/3 connection is closed'),
        _terminalStackTrace ?? StackTrace.current,
      );
    }
    await _ensureControlStream();
    final streamId = await _openStream(bidirectional: true);
    final goawayId = _peerGoawayId;
    if (goawayId != null && streamId >= goawayId) {
      _socket.streamReset(streamId, errorCode: 0x010b);
      throw Http3RequestRejectedException(
        streamId: streamId,
        goawayId: goawayId,
      );
    }
    final stream = _DatagramQuicStream(
      transport: this,
      id: streamId,
    );
    _streams[stream.id] = stream;
    return stream;
  }

  Uint8List encodeRequestHeaders(int streamId, RequestOptions options) {
    final headers = const Http3RequestWriter().requestHeaders(options);
    return Http3HeadersFrame(
      _qpackEncoder.encodeHeaders(streamId, headers),
    ).encode();
  }

  Future<Map<String, String>> decodeResponseHeaders(
    int streamId,
    List<int> headerBlock,
  ) {
    return _qpackDecoder.decodeHeaders(streamId, headerBlock);
  }

  void cancelResponseHeaders(int streamId) {
    _qpackDecoder.cancelStream(streamId);
  }

  void cancelRequest(
    int streamId, [
    Object? error,
    StackTrace? stackTrace,
  ]) {
    final stream = _streams.remove(streamId);
    if (stream == null) return;
    _pendingWrites.remove(streamId);
    _qpackDecoder.cancelStream(streamId);
    _qpackEncoder.cancelStream(streamId);
    _socket.streamStopSending(streamId, errorCode: 0x010c);
    _socket.streamReset(streamId, errorCode: 0x010c);
    if (error == null) {
      stream.terminate();
    } else {
      stream.fail(error, stackTrace);
    }
    _notifyDrained();
  }

  void sendStreamData(int streamId, List<int> data, {bool fin = false}) {
    if (_closed) return;
    if (data.isEmpty && !fin) return;
    final pending = _DatagramPendingWrite(
      Uint8List.fromList(data),
      fin: fin,
    );
    (_pendingWrites[streamId] ??= Queue()).add(pending);
    _flushWrites();
  }

  void _flushWrites() {
    if (_closed || _flushingWrites) return;
    _flushingWrites = true;
    try {
      for (final streamId in List<int>.of(_pendingWrites.keys)) {
        final writes = _pendingWrites[streamId];
        if (writes == null) continue;
        while (!_closed && writes.isNotEmpty) {
          final pending = writes.first;
          if (pending.offset < pending.data.length) {
            final written = _socket.streamWrite(
              streamId,
              pending.data,
              pending.offset,
              pending.data.length - pending.offset,
            );
            if (written < 0 || written > pending.data.length - pending.offset) {
              _failAll(StateError(
                'RawDatagramSecureSocket.streamWrite returned invalid '
                'length $written',
              ));
              return;
            }
            pending.offset += written;
            if (written == 0) break;
          }
          if (pending.offset == pending.data.length) {
            if (pending.fin) {
              _socket.streamClose(streamId);
            }
            writes.removeFirst();
          }
        }
        if (writes.isEmpty) {
          _pendingWrites.remove(streamId);
        }
      }
    } finally {
      _flushingWrites = false;
    }
  }

  Future<void> _ensureControlStream() {
    return _controlStreamFuture ??= _openControlStream();
  }

  Future<void> _openControlStream() async {
    if (_sentControlStream) return;
    _sentControlStream = true;
    final streamId = await _openStream(bidirectional: false);
    _controlStreamId = streamId;
    final random = Random.secure();
    final payload = Uint8List.fromList([
      ...QuicVariableLengthInteger.encode(Http3StreamType.control),
      ...Http3SettingsFrame(
          qpackMaxTableCapacity: _qpackMaximumTableCapacity,
          qpackBlockedStreams: _qpackMaximumBlockedStreams,
          additionalSettings: {
            // Grease
            33 + (31 * random.nextInt(1 << 32)):
                33 + (31 * random.nextInt(1 << 32))
          }).encode(),
    ]);
    sendStreamData(streamId, payload);
  }

  void _queueQpackEncoderInstructions(Uint8List instructions) {
    if (_closed || instructions.isEmpty) return;
    final streamId = _qpackEncoderStreamId;
    if (streamId != null) {
      sendStreamData(streamId, instructions);
      return;
    }
    _pendingQpackEncoderInstructions.add(instructions);
    final future = _qpackEncoderStreamFuture ??= _openQpackEncoderStream();
    unawaited(future.catchError(_failAll));
  }

  void _queueQpackDecoderInstructions(Uint8List instructions) {
    if (_closed || instructions.isEmpty) return;
    final streamId = _qpackDecoderStreamId;
    if (streamId != null) {
      sendStreamData(streamId, instructions);
      return;
    }
    _pendingQpackDecoderInstructions.add(instructions);
    final future = _qpackDecoderStreamFuture ??= _openQpackDecoderStream();
    unawaited(future.catchError(_failAll));
  }

  Future<void> _openQpackEncoderStream() async {
    final streamId = await _openStream(bidirectional: false);
    _qpackEncoderStreamId = streamId;
    sendStreamData(
      streamId,
      QuicVariableLengthInteger.encode(Http3StreamType.qpackEncoder),
    );
    while (_pendingQpackEncoderInstructions.isNotEmpty) {
      sendStreamData(
        streamId,
        _pendingQpackEncoderInstructions.removeFirst(),
      );
    }
  }

  Future<void> _openQpackDecoderStream() async {
    final streamId = await _openStream(bidirectional: false);
    _qpackDecoderStreamId = streamId;
    sendStreamData(
      streamId,
      QuicVariableLengthInteger.encode(Http3StreamType.qpackDecoder),
    );
    while (_pendingQpackDecoderInstructions.isNotEmpty) {
      sendStreamData(
        streamId,
        _pendingQpackDecoderInstructions.removeFirst(),
      );
    }
  }

  Future<int> _openStream({required bool bidirectional}) async {
    while (!_closed) {
      final streamId = bidirectional
          ? _socket.openBidirectionalStream()
          : _socket.openUnidirectionalStream();
      if (streamId >= 0) return streamId;
      final changed = _streamCapacityChanged ??= Completer<void>();
      await changed.future;
    }
    Error.throwWithStackTrace(
      _terminalError ?? StateError('HTTP/3 connection is closed'),
      _terminalStackTrace ?? StackTrace.current,
    );
  }

  void _signalStreamCapacity() {
    final changed = _streamCapacityChanged;
    _streamCapacityChanged = null;
    if (changed != null && !changed.isCompleted) {
      changed.complete();
    }
  }

  void _failStreamCapacity(Object error, [StackTrace? stackTrace]) {
    final changed = _streamCapacityChanged;
    _streamCapacityChanged = null;
    if (changed != null && !changed.isCompleted) {
      changed.completeError(error, stackTrace);
    }
  }

  void _handleSocketEvent(RawSocketEvent event) {
    if (_closed) return;
    if (event == RawSocketEvent.read) {
      _drainReads();
    } else if (event == RawSocketEvent.write) {
      _signalStreamCapacity();
      _flushWrites();
    } else if (event == RawSocketEvent.closed ||
        event == RawSocketEvent.readClosed) {
      final termination = _socket.termination;
      if (termination == null) {
        _closeAll();
      } else {
        _failAll(Http3ConnectionTerminatedException(termination));
      }
    }
  }

  void _handleSocketError(Object error, StackTrace stackTrace) {
    if (error is QuicConnectionException) {
      _failAll(
        Http3ConnectionTerminatedException(error.termination),
        stackTrace,
      );
      return;
    }
    _failAll(error, stackTrace);
  }

  void _drainReads() {
    _drainNewTokens();
    _drainResumptionStates();
    _drainControlStreamError();
    if (_closed) return;
    _acceptPeerStreams();
    _drainStreamReads();
    _drainPeerStreamReads();
    _drainDatagrams();
  }

  void _drainNewTokens() {
    while (!_closed) {
      final token = _socket.takeNewToken();
      if (token == null) return;
      onNewToken?.call(token);
    }
  }

  void _drainResumptionStates() {
    while (!_closed) {
      final state = _socket.takeResumptionState();
      if (state == null) return;
      onResumptionState?.call(state);
    }
  }

  void _drainControlStreamError() {
    for (final streamId in <int?>[
      _controlStreamId,
      _qpackEncoderStreamId,
      _qpackDecoderStreamId,
    ]) {
      if (streamId == null) continue;
      final errorCode = _socket.streamWriteErrorCode(streamId);
      if (errorCode != null) {
        _failAll(_Http3ApplicationException(
          0x0104,
          'Peer stopped critical HTTP/3 stream $streamId',
        ));
        return;
      }
    }
  }

  void _acceptPeerStreams() {
    while (!_closed) {
      final streamId = _socket.acceptStream();
      if (streamId < 0) return;
      _peerStreams[streamId] = _DatagramPeerStream(
        transport: this,
        id: streamId,
        bidirectional: _socket.isStreamBidirectional(streamId),
      );
    }
  }

  void _drainStreamReads() {
    final streams = List<_DatagramQuicStream>.of(_streams.values);
    for (final stream in streams) {
      final writeErrorCode = _socket.streamWriteErrorCode(stream.id);
      if (writeErrorCode != null) {
        _pendingWrites.remove(stream.id);
      }
      final errorCode = _socket.streamReadErrorCode(stream.id);
      if (errorCode != null) {
        stream.fail(_DatagramStreamException(stream.id, errorCode));
        _streams.remove(stream.id);
        _pendingWrites.remove(stream.id);
        _notifyDrained();
        continue;
      }
      while (!_closed) {
        final payload = _socket.streamRead(stream.id);
        if (payload == null) break;
        if (payload.isEmpty) {
          stream.terminate();
          _streams.remove(stream.id);
          _notifyDrained();
          break;
        }
        stream.addIncoming(payload);
      }
    }
  }

  void _drainPeerStreamReads() {
    final streams = List<_DatagramPeerStream>.of(_peerStreams.values);
    for (final stream in streams) {
      final errorCode = _socket.streamReadErrorCode(stream.id);
      if (errorCode != null) {
        if (stream.isCritical) {
          _failAll(_Http3ApplicationException(
            0x0104,
            'Peer reset critical HTTP/3 stream ${stream.id}',
          ));
        } else {
          _failAll(_DatagramStreamException(stream.id, errorCode));
        }
        return;
      }
      while (!_closed) {
        final payload = _socket.streamRead(stream.id);
        if (payload == null) break;
        if (payload.isEmpty) {
          _peerStreams.remove(stream.id);
          if (stream.isCritical) {
            _failAll(const _Http3ApplicationException(
              0x0104,
              'Peer closed a critical HTTP/3 stream',
            ));
            return;
          }
          break;
        }
        try {
          stream.addIncoming(payload);
        } on Object catch (error, stackTrace) {
          _failAll(error, stackTrace);
          return;
        }
      }
    }
  }

  void _registerPeerStreamType(int streamId, int type) {
    if (type != Http3StreamType.control &&
        type != Http3StreamType.qpackEncoder &&
        type != Http3StreamType.qpackDecoder) {
      return;
    }
    final previous = _peerCriticalStreams[type];
    if (previous != null && previous != streamId) {
      throw _Http3ApplicationException(
        0x0103,
        'Peer created duplicate HTTP/3 stream type 0x${type.toRadixString(16)}',
      );
    }
    _peerCriticalStreams[type] = streamId;
  }

  void _handlePeerControlFrames(List<Http3Frame> frames) {
    for (final frame in frames) {
      if (frame is Http3SettingsFrame) {
        _qpackEncoder.configure(
          maximumTableCapacity: frame.qpackMaxTableCapacity,
          maximumBlockedStreams: frame.qpackBlockedStreams,
        );
      } else if (frame is Http3GoawayFrame) {
        _handleGoaway(frame.id);
      }
    }
  }

  void _handleGoaway(int id) {
    if ((id & 0x03) != 0) {
      throw _Http3ApplicationException(
        0x0108,
        'Server GOAWAY ID $id is not a client-initiated bidirectional stream',
      );
    }
    final previous = _peerGoawayId;
    if (previous != null && id > previous) {
      throw _Http3ApplicationException(
        0x0108,
        'Server increased GOAWAY ID from $previous to $id',
      );
    }
    _peerGoawayId = id;
    onGoaway?.call(id);

    for (final streamId in List<int>.of(_streams.keys)) {
      if (streamId < id) continue;
      final stream = _streams.remove(streamId)!;
      _pendingWrites.remove(streamId);
      _socket.streamReset(streamId, errorCode: 0x010b);
      stream.fail(Http3RequestRejectedException(
        streamId: streamId,
        goawayId: id,
      ));
    }
    _notifyDrained();
  }

  void _notifyDrained() {
    if (_peerGoawayId == null || _streams.isNotEmpty || _drainedNotified) {
      return;
    }
    _drainedNotified = true;
    scheduleMicrotask(() => onDrained?.call());
  }

  void _drainDatagrams() {
    while (true) {
      final payload = _socket.receive();
      if (payload == null) return;
      // RawDatagramSecureSocket.receive() is only for unreliable QUIC
      // DATAGRAM frames. HTTP/3 request/response bodies arrive through
      // reliable streamRead() above.
    }
  }

  Future<void> close() async {
    if (_closed) return;
    await _subscription.cancel();
    _closeAll();
    await _socket.close();
  }

  void _closeAll() {
    if (_closed) return;
    _closed = true;
    _qpackDecoder.failBlocked(StateError('HTTP/3 connection is closed'));
    for (final stream in _streams.values) {
      stream.terminate();
    }
    _streams.clear();
    _peerStreams.clear();
    _pendingWrites.clear();
    _failStreamCapacity(StateError('HTTP/3 connection is closed'));
  }

  void _failAll(Object error, [StackTrace? stackTrace]) {
    if (_closed) return;
    _closed = true;
    _terminalError = error;
    _terminalStackTrace = stackTrace;
    _qpackDecoder.failBlocked(error, stackTrace);
    final applicationError = switch (error) {
      QpackException() => error.errorCode,
      _Http3ApplicationException() => error.errorCode,
      _ => null,
    };
    if (applicationError != null) {
      unawaited(_socket.close(errorCode: applicationError, reason: '$error'));
    }
    for (final stream in _streams.values) {
      stream.fail(error, stackTrace);
    }
    _streams.clear();
    _peerStreams.clear();
    _pendingWrites.clear();
    _failStreamCapacity(error, stackTrace);
  }
}

class _DatagramPendingWrite {
  _DatagramPendingWrite(this.data, {required this.fin});

  final Uint8List data;
  final bool fin;
  int offset = 0;
}

class _DatagramStreamException implements Exception {
  const _DatagramStreamException(this.streamId, this.errorCode);

  final int streamId;
  final int errorCode;

  @override
  String toString() => 'QUIC stream $streamId was terminated by the peer '
      '(application error $errorCode)';
}

class _Http3ApplicationException implements Exception {
  const _Http3ApplicationException(this.errorCode, this.message);

  final int errorCode;
  final String message;

  @override
  String toString() =>
      'HTTP/3 error 0x${errorCode.toRadixString(16)}: $message';
}

class _DatagramPeerStream {
  _DatagramPeerStream({
    required this.transport,
    required this.id,
    required this.bidirectional,
  });

  final _DatagramQuicTransport transport;
  final int id;
  final bool bidirectional;
  final _typePrefix = <int>[];
  final _controlFrames = Http3FrameDecoder();
  int? _type;

  bool get isCritical =>
      _type == Http3StreamType.control ||
      _type == Http3StreamType.qpackEncoder ||
      _type == Http3StreamType.qpackDecoder;

  void addIncoming(Uint8List data) {
    if (bidirectional) {
      return;
    }
    if (_type != null) {
      _handlePayload(data);
      return;
    }

    _typePrefix.addAll(data);
    if (_typePrefix.isEmpty) return;
    final encodedLength = 1 << (_typePrefix.first >> 6);
    if (_typePrefix.length < encodedLength) return;
    final decoded = QuicVariableLengthInteger.decode(_typePrefix);
    _type = decoded.value;
    transport._registerPeerStreamType(id, decoded.value);
    final remainder = Uint8List.fromList(
      _typePrefix.sublist(decoded.bytesRead),
    );
    _typePrefix.clear();
    _handlePayload(remainder);
  }

  void _handlePayload(Uint8List data) {
    if (_type == Http3StreamType.control && data.isNotEmpty) {
      transport._handlePeerControlFrames(_controlFrames.add(data));
    } else if (_type == Http3StreamType.qpackEncoder && data.isNotEmpty) {
      transport._qpackDecoder.addEncoderStreamData(data);
    } else if (_type == Http3StreamType.qpackDecoder && data.isNotEmpty) {
      transport._qpackEncoder.addDecoderStreamData(data);
    }
  }
}

class _DatagramQuicStream implements QuicClientStream {
  _DatagramQuicStream({
    required this.transport,
    required this.id,
  });

  final _DatagramQuicTransport transport;
  final int id;
  final _incoming = StreamController<Uint8List>(sync: true);

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  @override
  void add(List<int> bytes) {
    transport.sendStreamData(id, bytes);
  }

  @override
  Future<void> close() async {
    transport.sendStreamData(id, const <int>[], fin: true);
  }

  @override
  void terminate() {
    if (!_incoming.isClosed) {
      _incoming.close();
    }
  }

  void addIncoming(Uint8List data) {
    if (_incoming.isClosed) return;
    _incoming.add(data);
  }

  void fail(Object error, [StackTrace? stackTrace]) {
    if (!_incoming.isClosed) {
      _incoming.addError(error, stackTrace);
      _incoming.close();
    }
  }
}

class _DatagramHttp3ConnectionState {
  _DatagramHttp3ConnectionState(this.connection);

  final _DatagramHttp3ClientConnection connection;
  bool isActive = true;
  late int latestIdleTimeStamp;
  Timer? _timer;

  _DatagramHttp3ClientConnection get activeConnection {
    isActive = true;
    latestIdleTimeStamp = DateTime.now().millisecondsSinceEpoch;
    return connection;
  }

  void delayClose(int idleTimeout, void Function() callback) {
    idleTimeout = idleTimeout < 100 ? 100 : idleTimeout;
    _startTimer(callback, idleTimeout, idleTimeout);
  }

  Future<void> dispose() async {
    _timer?.cancel();
    await connection.finish();
  }

  void _startTimer(void Function() callback, int duration, int idleTimeout) {
    _timer = Timer(Duration(milliseconds: duration), () {
      if (!isActive) {
        final interval =
            DateTime.now().millisecondsSinceEpoch - latestIdleTimeStamp;
        if (interval >= duration) {
          return callback();
        }
        return _startTimer(callback, duration - interval, idleTimeout);
      }
      _startTimer(callback, idleTimeout, idleTimeout);
    });
  }
}
