import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  test('unblocks an RFC 9204 field section after fragmented inserts', () async {
    final decoderInstructions = <int>[];
    final decoder = QpackDecoder(
      maximumTableCapacity: 220,
      maximumBlockedStreams: 1,
      onDecoderInstructions: decoderInstructions.addAll,
    );

    // RFC 9204 Appendix B.2: the field section can arrive before the
    // independently delivered encoder-stream instructions.
    final decoded = decoder.decodeHeaders(4, [0x03, 0x81, 0x10, 0x11]);
    var completed = false;
    decoded.whenComplete(() => completed = true);

    decoder.addEncoderStreamData([0x3f]);
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse);

    decoder.addEncoderStreamData([
      0xbd,
      0x01,
      0xc0,
      0x0f,
      ...'www.example.com'.codeUnits,
      0xc1,
      0x0c,
      ...'/sample/path'.codeUnits,
    ]);

    expect(await decoded, {
      ':authority': 'www.example.com',
      ':path': '/sample/path',
    });
    expect(decoder.insertCount, 2);
    expect(decoderInstructions, [0x02, 0x84]);
  });

  test('encodes dynamic references and processes decoder feedback', () async {
    final encoderInstructions = <int>[];
    final encoder = QpackEncoder(
      preferredTableCapacity: 220,
      onEncoderInstructions: encoderInstructions.addAll,
    );
    encoder.configure(
      maximumTableCapacity: 220,
      maximumBlockedStreams: 1,
    );

    final block = encoder.encodeHeaders(0, {'custom-key': 'custom-value'});
    final decoderInstructions = <int>[];
    final decoder = QpackDecoder(
      maximumTableCapacity: 220,
      maximumBlockedStreams: 1,
      onDecoderInstructions: decoderInstructions.addAll,
    );
    decoder.addEncoderStreamData(encoderInstructions);

    expect(await decoder.decodeHeaders(0, block), {
      'custom-key': 'custom-value',
    });
    expect(decoderInstructions, [0x01, 0x80]);

    encoder.addDecoderStreamData(decoderInstructions.sublist(0, 1));
    encoder.addDecoderStreamData(decoderInstructions.sublist(1));
    expect(encoder.knownReceivedCount, 1);

    encoderInstructions.clear();
    final repeated = encoder.encodeHeaders(
      4,
      {'custom-key': 'custom-value'},
    );
    expect(encoderInstructions, isEmpty);
    expect(repeated, [0x02, 0x00, 0x80]);
    expect(
      repeated.length,
      lessThan(
        const QpackHeaderBlockEncoder()
            .encodeHeaders({'custom-key': 'custom-value'}).length,
      ),
    );
  });

  test('never inserts sensitive request fields', () {
    final encoderInstructions = <int>[];
    final encoder = QpackEncoder(
      preferredTableCapacity: 220,
      onEncoderInstructions: encoderInstructions.addAll,
    );
    encoder.configure(
      maximumTableCapacity: 220,
      maximumBlockedStreams: 1,
    );
    encoderInstructions.clear();

    encoder.encodeHeaders(0, {'authorization': 'Bearer secret'});

    expect(encoderInstructions, isEmpty);
    expect(encoder.insertCount, 0);
  });

  test('decodes RFC duplicate, literal insert, and relative references',
      () async {
    final decoderInstructions = <int>[];
    final decoder = QpackDecoder(
      maximumTableCapacity: 220,
      maximumBlockedStreams: 1,
      onDecoderInstructions: decoderInstructions.addAll,
    );
    decoder.addEncoderStreamData([
      0x3f,
      0xbd,
      0x01,
      0xc0,
      0x0f,
      ...'www.example.com'.codeUnits,
      0xc1,
      0x0c,
      ...'/sample/path'.codeUnits,
    ]);
    // RFC 9204 Appendix B.3 and B.4.
    decoder.addEncoderStreamData([
      0x4a,
      ...'custom-key'.codeUnits,
      0x0c,
      ...'custom-value'.codeUnits,
      0x02,
    ]);

    expect(await decoder.decodeHeaders(8, [0x05, 0x00, 0x80, 0xc1, 0x81]), {
      ':authority': 'www.example.com',
      ':path': '/',
      'custom-key': 'custom-value',
    });
    expect(decoder.insertCount, 4);
    expect(decoderInstructions, [0x02, 0x02, 0x88]);
  });

  test('enforces the advertised blocked-stream limit', () async {
    final decoder = QpackDecoder(
      maximumTableCapacity: 220,
      maximumBlockedStreams: 1,
    );
    final first = decoder.decodeHeaders(4, [0x03, 0x81, 0x10, 0x11]);

    await expectLater(
      decoder.decodeHeaders(8, [0x03, 0x81, 0x10, 0x11]),
      throwsA(
        isA<QpackException>().having(
          (error) => error.errorCode,
          'errorCode',
          QpackErrorCode.decompressionFailed,
        ),
      ),
    );

    decoder.addEncoderStreamData([
      0x3f,
      0xbd,
      0x01,
      0xc0,
      0x0f,
      ...'www.example.com'.codeUnits,
      0xc1,
      0x0c,
      ...'/sample/path'.codeUnits,
    ]);
    expect((await first)[':authority'], 'www.example.com');
  });
}
