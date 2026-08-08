import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http2_adapter.dart';
import 'package:test/test.dart';

void main() {
	test('httpbin.org/anything', () async {
		final context = SecurityContext();
		context.minimumTlsProtocolVersion = TlsProtocolVersion.tls1;
		final dio = Dio()
      ..httpClientAdapter = Http2Adapter(ConnectionManager(
        idleTimeout: 10,
				onClientCreate: (url, setting) {
					setting.context = context;
					setting.onBadCertificate = (cert) {
						print('bad cert $cert');
						return true;
					};
				}
      ));

    final res = await dio.get('https://tls.browserleaks.com/', options: Options(
			responseType: ResponseType.plain
		));
    print(res.data);
	});
}
