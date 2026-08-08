part of '../http3_adapter.dart';

class _Http3AlternativeService {
  const _Http3AlternativeService({
    required this.host,
    required this.port,
    required this.expiresAt,
  });

  static final clear = _Http3AlternativeService(
    host: '',
    port: 0,
    expiresAt: DateTime.fromMillisecondsSinceEpoch(0),
  );

  final String host;
  final int port;
  final DateTime expiresAt;

  @override
  String toString() =>
      '_Http3AlternativeService($host, port: $port, expiresAt: $expiresAt)';
}

class _FailedHttp3AlternativeService {
  const _FailedHttp3AlternativeService({
    required this.host,
    required this.port,
    required this.retryAfter,
  });

  final String host;
  final int port;
  final DateTime retryAfter;

  bool matches(_Http3AlternativeService alternative) =>
      port == alternative.port &&
      host.toLowerCase() == alternative.host.toLowerCase();
}
