part of 'http2_adapter.dart';

/// Default implementation of ConnectionManager
class _ConnectionManager implements ConnectionManager {
  /// Callback when socket created.
  ///
  /// We can set trusted certificates and handler
  /// for unverifiable certificates.
  final void Function(Uri uri, ClientSetting)? onClientCreate;

  /// Sets the idle timeout(milliseconds) of non-active persistent
  /// connections. For the sake of socket reuse feature with http/2,
  /// the value should not be less than 1000 (1s).
  final int _idleTimeout;

  /// Saving the reusable connections
  final _transportsMap = <String, _ClientTransportConnectionState>{};

  /// Saving the connecting futures
  final _connectFutures = <String, Future<_ClientTransportConnectionState>>{};

  bool _closed = false;
  bool _forceClosed = false;

  _ConnectionManager({int? idleTimeout, this.onClientCreate})
      : _idleTimeout = idleTimeout ?? 1000;

  @override
  Future<ConnectionTask<Socket>> connectionFactory(Uri url, String? proxyHost, int? proxyPort) async {
    final domain = '${url.host}:${url.port}';
    ClientSetting? clientConfig;
    final transport = _transportsMap[domain]?.transport;
    if (transport is _ClientTransportConnectionWrapper1) {
      try {
        transport.socket?.address;
      }
      on SocketException {
        transport.socket = null;
      }
      final socket = transport.socket;
      if (socket != null) {
        transport._onActiveStateChanged(true);
        transport.socket = null; // Can't be used again
        return ConnectionTask.fromSocket(Future.value(socket), () {});
      }
      transport._onActiveStateChanged(false);
      clientConfig = transport.clientConfig;
    }
    // Fallback to default factory
    if (url.isScheme('https')) {
      return await SecureSocket.startConnect(
        url.host,
        url.port,
        context: clientConfig?.context,
        onBadCertificate: clientConfig?.onBadCertificate
      );
    }
    return await Socket.startConnect(url.host, url.port);
  }

  @override
  Future<ClientTransportConnection?> getConnection(
      RequestOptions options) async {
    if (_closed) {
      throw Exception(
          "Can't establish connection after [ConnectionManager] closed!");
    }
    var uri = options.uri;
    var domain = '${uri.host}:${uri.port}';
    var transportState = _transportsMap[domain];
    if (transportState == null || !transportState.transport.isOpen) {
      transportState?.dispose();
      var _initFuture = _connectFutures[domain];
      if (_initFuture == null) {
        _connectFutures[domain] = _initFuture = _connect(options);
      }
      transportState = await _initFuture;
      if (_forceClosed) {
        transportState.dispose();
      } else {
        _transportsMap[domain] = transportState;
        var _ = _connectFutures.remove(domain);
      }
    }
    final activeWrapper = transportState.activeTransport;
    if (activeWrapper is _ClientTransportConnectionWrapper2) {
      return activeWrapper.transport;
    }
    return null;
  }

  Future<_ClientTransportConnectionState> _connect(
      RequestOptions options) async {
    var uri = options.uri;
    var domain = '${uri.host}:${uri.port}';
    var clientConfig = ClientSetting();
    if (onClientCreate != null) {
      onClientCreate!(uri, clientConfig);
    }
    _ClientTransportConnectionWrapper transport;
    if (uri.isScheme('https')) {
      late SecureSocket socket;
      try {
        // Create socket
        socket = await SecureSocket.connect(
          uri.host,
          uri.port,
          timeout: options.connectTimeout > 0
              ? Duration(milliseconds: options.connectTimeout)
              : null,
          context: clientConfig.context,
          onBadCertificate: clientConfig.onBadCertificate,
          supportedProtocols: ['h2', 'http/1.1']
        );
      } on SocketException catch (e) {
        if (e.osError == null) {
          if (e.message.contains('timed out')) {
            throw DioError(
              requestOptions: options,
              error: 'Connecting timed out [${options.connectTimeout}ms]',
              type: DioErrorType.connectTimeout,
            );
          }
        }
        rethrow;
      }
      if (socket.selectedProtocol == 'h2') {
        // HTTPS 2.0
        transport = _ClientTransportConnectionWrapper2(ClientTransportConnection.viaSocket(socket));
      }
      else {
        // HTTPS 1.x
        transport = _ClientTransportConnectionWrapper1(clientConfig, domain, socket);
      }
    }
    else {
      // HTTP 1.x
      transport = _ClientTransportConnectionWrapper1(clientConfig, domain, null);
    }
    // Config a ClientTransportConnection and save it
    var _transportState = _ClientTransportConnectionState(transport);
    transport.onActiveStateChanged = (bool isActive) {
      _transportState.isActive = isActive;
      if (!isActive) {
        _transportState.latestIdleTimeStamp =
            DateTime.now().millisecondsSinceEpoch;
      }
    };
    //
    _transportState.delayClose(
      _closed ? 50 : _idleTimeout,
      () {
        _transportsMap.remove(domain);
        _transportState.transport.finish();
      },
    );
    return _transportState;
  }

  @override
  void removeConnection(ClientTransportConnection transport) {
    _ClientTransportConnectionState? _transportState;
    _transportsMap.removeWhere((_, state) {
      final otherTransport = state.transport;
      if (otherTransport is _ClientTransportConnectionWrapper2 && otherTransport.transport == transport) {
        _transportState = state;
        return true;
      }
      return false;
    });
    _transportState?.dispose();
  }

  @override
  void close({bool force = false}) {
    _closed = true;
    _forceClosed = force;
    if (force) {
      _transportsMap.forEach((key, value) => value.dispose());
    }
  }
}

class _ClientTransportConnectionState {
  _ClientTransportConnectionState(this.transport);

  _ClientTransportConnectionWrapper transport;

  _ClientTransportConnectionWrapper get activeTransport {
    isActive = true;
    latestIdleTimeStamp = DateTime.now().millisecondsSinceEpoch;
    return transport;
  }

  bool isActive = true;
  late int latestIdleTimeStamp;
  Timer? _timer;

  void delayClose(int idleTimeout, void Function() callback) {
    idleTimeout = idleTimeout < 100 ? 100 : idleTimeout;
    _startTimer(callback, idleTimeout, idleTimeout);
  }

  void dispose() {
    _timer?.cancel();
    transport.finish();
  }

  void _startTimer(void Function() callback, int duration, int idleTimeout) {
    _timer = Timer(Duration(milliseconds: duration), () {
      if (!isActive) {
        var interval =
            DateTime.now().millisecondsSinceEpoch - latestIdleTimeStamp;
        if (interval >= duration) {
          return callback();
        }
        return _startTimer(callback, duration - interval, idleTimeout);
      }
      // if active
      _startTimer(callback, idleTimeout, idleTimeout);
    });
  }
}

abstract class _ClientTransportConnectionWrapper {
  bool get isOpen;
  set onActiveStateChanged(void Function(bool) cb);
  Future<void> finish();
  @override
  String toString() => '$runtimeType(${identityHashCode(this)})';
}

class _ClientTransportConnectionWrapper1 extends _ClientTransportConnectionWrapper {
  final ClientSetting clientConfig;
  final String domain;
  SecureSocket? socket;
  void Function(bool) _onActiveStateChanged = (_) {};
  _ClientTransportConnectionWrapper1(this.clientConfig, this.domain, this.socket) {
    socket?.done.then((_) {
      _onActiveStateChanged(false);
      socket = null;
    });
  }
  @override
  bool get isOpen => socket != null;
  @override
  set onActiveStateChanged(cb) {
    _onActiveStateChanged = cb;
  }
  @override
  Future<void> finish() async {
    final s = socket;
    socket = null;
    await s?.close();
  }
}

class _ClientTransportConnectionWrapper2 extends _ClientTransportConnectionWrapper {
  final ClientTransportConnection transport;
  _ClientTransportConnectionWrapper2(this.transport);
  @override
  bool get isOpen => transport.isOpen;
  @override
  set onActiveStateChanged(Function(bool) cb) => transport.onActiveStateChanged = cb;
  @override
  Future<void> finish() async {
    await transport.finish();
  }
}
