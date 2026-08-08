import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('round trips a GOAWAY frame', () {
    final encoded = Http3GoawayFrame(16).encode();
    final decoded = Http3FrameCodec.decodeAll(encoded);

    expect(decoded.single, isA<Http3GoawayFrame>());
    expect((decoded.single as Http3GoawayFrame).id, 16);
  });

  test('decodes a GOAWAY frame split across control-stream reads', () {
    final encoded = Http3GoawayFrame(16384).encode();
    final decoder = Http3FrameDecoder();

    expect(decoder.add(encoded.sublist(0, 3)), isEmpty);
    final decoded = decoder.add(encoded.sublist(3));

    expect((decoded.single as Http3GoawayFrame).id, 16384);
  });

  test('rejects trailing GOAWAY payload bytes', () {
    expect(
      () => Http3FrameCodec.decodeAll(const [0x07, 0x02, 0x00, 0x00]),
      throwsFormatException,
    );
  });
}
