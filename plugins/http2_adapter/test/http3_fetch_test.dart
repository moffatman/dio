import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('manager fetches a public HTTP/3 endpoint', () async {
    final manager = Http3ConnectionManager(
        preferHttp3WithoutAltSvc: true,
        onClientCreate: (url, clientSetting) {
          clientSetting.onBadCertificate = (cert) {
            print('DART ONBADCERTIFICATE $cert');
            return true;
          };
        });
    final options = RequestOptions(
      path: 'https://cloudflare-quic.com/',
      //path: 'https://127.0.0.1:4433/',
      method: 'GET',
    );

    try {
      print('getConnection');
      final connection = await manager.getConnection(options);

      expect(connection, isNotNull);
      print(connection);

      final response = await connection!.fetch(options, null, null);
      final builder = BytesBuilder(copy: true);
      await for (final chunk in response.stream) {
        print('got chunk $chunk');
        builder.add(chunk);
      }
      print('callum1');
      final bytes = builder.takeBytes();
      print(bytes);
      print(utf8.decode(bytes));

      expect(response.statusCode, 200);
      expect(bytes.length, greaterThan(0));
    } finally {
      manager.close(force: true);
    }
  }, timeout: const Timeout(Duration(seconds: 30)));
}
