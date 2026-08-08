import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http2_adapter.dart';
import 'package:test/test.dart';

void main() {
	test('httpbin.org/anything', () async {
		final dio = Dio()
      ..httpClientAdapter = Http2Adapter(ConnectionManager(
        idleTimeout: 10,
      ));

    final res = await dio.post('https://httpbin.org/anything', data: FormData.fromMap({
			'fileSpoiler': ''
		}), options: Options(
			headers: {
				'accept': '*/*',
				'user-agent': 'curl/8.7.1'
			}
		));
    print(res.data);
	});
}
