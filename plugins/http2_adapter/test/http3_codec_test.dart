import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio_http2_adapter/dio_http3_adapter.dart';
import 'package:test/test.dart';

void main() {
  group('QUIC variable-length integer', () {
    test('encodes values with the shortest representation', () {
      expect(QuicVariableLengthInteger.encode(37), [0x25]);
      expect(QuicVariableLengthInteger.encode(15293), [0x7b, 0xbd]);
      expect(QuicVariableLengthInteger.decode([0x7b, 0xbd]).value, 15293);
    });
  });

  group('QUIC Initial packet', () {
    test('round trips unprotected long-header fields', () {
      final packet = QuicInitialPacket(
        destinationConnectionId: QuicConnectionId([1, 2, 3, 4]),
        sourceConnectionId: QuicConnectionId([5, 6, 7, 8]),
        payload: QuicCryptoFrame(0, [0xaa, 0xbb]).encode(),
      );

      final decoded = QuicPacketCodec.decodeInitial(
        QuicPacketCodec.encodeInitial(packet),
      );

      expect(decoded.version, 0x00000001);
      expect(decoded.destinationConnectionId.bytes, [1, 2, 3, 4]);
      expect(decoded.sourceConnectionId.bytes, [5, 6, 7, 8]);
      expect(decoded.packetNumber, 0);
      final frames = QuicFrameCodec.decodeAll(decoded.payload);
      expect(frames, hasLength(1));
      expect((frames.single as QuicCryptoFrame).data, [0xaa, 0xbb]);
    });
  });

  group('HTTP/3 frames', () {
    test('round trips settings', () {
      final settings = Http3SettingsFrame(
        qpackMaxTableCapacity: 128,
        qpackBlockedStreams: 4,
        enableConnectProtocol: true,
      );

      final decoded = Http3FrameCodec.decodeAll(settings.encode());

      expect(decoded, hasLength(1));
      final decodedSettings = decoded.single as Http3SettingsFrame;
      expect(decodedSettings.qpackMaxTableCapacity, 128);
      expect(decodedSettings.qpackBlockedStreams, 4);
      expect(decodedSettings.enableConnectProtocol, isTrue);
    });

    test('encodes request headers as a HEADERS frame', () {
      final options = RequestOptions(
        path: 'https://example.com/search?q=dart',
        method: 'GET',
      );
      final encoded = const Http3RequestWriter().encodeRequestHeaders(options);
      final frames = Http3FrameCodec.decodeAll(encoded);

      expect(frames.single, isA<Http3HeadersFrame>());
      final headerBlock = (frames.single as Http3HeadersFrame).headerBlock;
      expect(headerBlock, isA<Uint8List>());
      final headers =
          const QpackHeaderBlockDecoder().decodeHeaders(headerBlock);
      expect(headers[':method'], 'GET');
      expect(headers[':path'], '/search?q=dart');
    });

    test('decodes frames split across stream chunks', () {
      final encoded = Http3DataFrame([1, 2, 3]).encode();
      final decoder = Http3FrameDecoder();

      expect(decoder.add(encoded.sublist(0, 2)), isEmpty);
      final frames = decoder.add(encoded.sublist(2));

      expect(frames.single, isA<Http3DataFrame>());
      expect((frames.single as Http3DataFrame).data, [1, 2, 3]);
    });

    test('streams DATA payload before the complete frame arrives', () {
      final encoded = Http3DataFrame(List<int>.generate(64, (i) => i)).encode();
      final decoder = Http3FrameDecoder(streamDataFrames: true);
      final chunks = <int>[];

      for (var offset = 0; offset < encoded.length; offset += 7) {
        final end = offset + 7 < encoded.length ? offset + 7 : encoded.length;
        for (final frame in decoder.add(encoded.sublist(offset, end))) {
          chunks.addAll((frame as Http3DataFrame).data);
        }
      }

      expect(chunks, List<int>.generate(64, (i) => i));
    });
  });

  group('HTTP/3 discovery', () {
    test('learns and cools down Alt-Svc HTTP/3 origins', () {
      final manager = Http3ConnectionManager();
      final options = RequestOptions(path: 'https://example.com/');

      expect(manager.shouldAttemptHttp3(options), isFalse);

      manager.recordResponseHeaders(options.uri, {
        'alt-svc': ['h3=":443"; ma=60'],
      });
      expect(manager.shouldAttemptHttp3(options), isTrue);

      manager.markHttp3Unavailable(options.uri);
      expect(manager.shouldAttemptHttp3(options), isFalse);

      manager.recordResponseHeaders(options.uri, {
        'alt-svc': ['h3=":443"; ma=60'],
      });
      expect(
        manager.shouldAttemptHttp3(options),
        isFalse,
        reason: 'the same advertisement must not clear its failure cooldown',
      );

      manager.recordResponseHeaders(options.uri, {
        'alt-svc': ['h3="quic.example.com:8443"; ma=60'],
      });
      expect(
        manager.shouldAttemptHttp3(options),
        isTrue,
        reason: 'a different advertised endpoint can be attempted immediately',
      );
      manager.close(force: true);
    });

    test('times out and cools down an unreachable Alt-Svc endpoint', () async {
      final blackhole = await RawDatagramSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      final manager = Http3ConnectionManager(
        http3ConnectTimeout: const Duration(milliseconds: 100),
      );
      final options = RequestOptions(path: 'https://example.com/');
      final advertisement = 'h3="127.0.0.1:${blackhole.port}"; ma=60';
      manager.recordResponseHeaders(options.uri, {
        'alt-svc': [advertisement],
      });

      try {
        final watch = Stopwatch()..start();
        await expectLater(
          manager.getConnection(options),
          throwsA(isA<SocketException>()),
        );
        expect(watch.elapsed, lessThan(const Duration(seconds: 2)));
        expect(manager.shouldAttemptHttp3(options), isFalse);

        manager.recordResponseHeaders(options.uri, {
          'alt-svc': [advertisement],
        });
        expect(manager.shouldAttemptHttp3(options), isFalse);
      } finally {
        manager.close(force: true);
        blackhole.close();
      }
    });

    test('clears cached HTTP/3 alternatives', () {
      final manager = Http3ConnectionManager();
      final options = RequestOptions(path: 'https://example.com/');

      manager.recordResponseHeaders(options.uri, {
        'alt-svc': ['h3=":443"; ma=60'],
      });
      manager.recordResponseHeaders(options.uri, {
        'alt-svc': ['clear'],
      });

      expect(manager.shouldAttemptHttp3(options), isFalse);
    });

    test('manager fetches a public HTTP/3 endpoint', () async {
      final manager = Http3ConnectionManager(
        preferHttp3WithoutAltSvc: true,
      );
      final options = RequestOptions(
        path: 'https://cloudflare-quic.com/',
        method: 'GET',
      );

      try {
        final connection = await manager.getConnection(options);

        expect(connection, isNotNull);

        final response = await connection!.fetch(options, null, null);
        final bodyLength = await response.stream.fold<int>(
          0,
          (total, chunk) => total + chunk.length,
        );

        expect(response.statusCode, 200);
        expect(bodyLength, greaterThan(0));
      } finally {
        manager.close(force: true);
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });
}
