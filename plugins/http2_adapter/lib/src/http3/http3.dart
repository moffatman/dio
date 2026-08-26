part of '../http3_adapter.dart';

class Http3FrameType {
  static const int data = 0x00;
  static const int headers = 0x01;
  static const int cancelPush = 0x03;
  static const int settings = 0x04;
  static const int pushPromise = 0x05;
  static const int goaway = 0x07;
  static const int maxPushId = 0x0d;
}

class Http3StreamType {
  static const int control = 0x00;
  static const int push = 0x01;
  static const int qpackEncoder = 0x02;
  static const int qpackDecoder = 0x03;
}

abstract class Http3Frame {
  int get type;

  Uint8List encodePayload();

  Uint8List encode() {
    final payload = encodePayload();
    final writer = _QuicWriter();
    writer
      ..writeVarInt(type)
      ..writeVarInt(payload.length)
      ..writeBytes(payload);
    return writer.takeBytes();
  }
}

class Http3DataFrame extends Http3Frame {
  Http3DataFrame(List<int> data) : data = Uint8List.fromList(data);

  Http3DataFrame._fromBytes(this.data);

  @override
  int get type => Http3FrameType.data;

  final Uint8List data;

  @override
  Uint8List encodePayload() => data;
}

class Http3HeadersFrame extends Http3Frame {
  Http3HeadersFrame(List<int> headerBlock)
      : headerBlock = Uint8List.fromList(headerBlock);

  @override
  int get type => Http3FrameType.headers;

  final Uint8List headerBlock;

  @override
  Uint8List encodePayload() => headerBlock;
}

class Http3SettingsFrame extends Http3Frame {
  Http3SettingsFrame({
    this.qpackMaxTableCapacity = 0,
    this.qpackBlockedStreams = 0,
    this.enableConnectProtocol = false,
    Map<int, int>? additionalSettings,
  }) : additionalSettings = additionalSettings ?? const <int, int>{};

  static const int qpackMaxTableCapacityId = 0x01;
  static const int maxFieldSectionSizeId = 0x06;
  static const int qpackBlockedStreamsId = 0x07;
  static const int enableConnectProtocolId = 0x08;

  @override
  int get type => Http3FrameType.settings;

  final int qpackMaxTableCapacity;
  final int qpackBlockedStreams;
  final bool enableConnectProtocol;
  final Map<int, int> additionalSettings;

  @override
  Uint8List encodePayload() {
    final writer = _QuicWriter();
    _writeSetting(writer, qpackMaxTableCapacityId, qpackMaxTableCapacity);
    _writeSetting(writer, qpackBlockedStreamsId, qpackBlockedStreams);
    if (enableConnectProtocol) {
      _writeSetting(writer, enableConnectProtocolId, 1);
    }
    additionalSettings.forEach((id, value) {
      _writeSetting(writer, id, value);
    });
    return writer.takeBytes();
  }

  static void _writeSetting(_QuicWriter writer, int id, int value) {
    writer
      ..writeVarInt(id)
      ..writeVarInt(value);
  }
}

class Http3GoawayFrame extends Http3Frame {
  Http3GoawayFrame(this.id);

  @override
  int get type => Http3FrameType.goaway;

  final int id;

  @override
  Uint8List encodePayload() => QuicVariableLengthInteger.encode(id);
}

class Http3FrameCodec {
  static List<Http3Frame> decodeAll(List<int> bytes) {
    final reader = _QuicReader(bytes);
    final frames = <Http3Frame>[];
    while (!reader.isDone) {
      final type = reader.readVarInt();
      final length = reader.readVarInt();
      final payload = reader.readBytes(length);
      if (type == Http3FrameType.data) {
        frames.add(Http3DataFrame(payload));
      } else if (type == Http3FrameType.headers) {
        frames.add(Http3HeadersFrame(payload));
      } else if (type == Http3FrameType.settings) {
        frames.add(_decodeSettings(payload));
      } else if (type == Http3FrameType.goaway) {
        frames.add(_decodeGoaway(payload));
      }
    }
    return frames;
  }

  static Http3SettingsFrame _decodeSettings(List<int> payload) {
    final reader = _QuicReader(payload);
    var qpackMaxTableCapacity = 0;
    var qpackBlockedStreams = 0;
    var enableConnectProtocol = false;
    final additionalSettings = <int, int>{};
    while (!reader.isDone) {
      final id = reader.readVarInt();
      final value = reader.readVarInt();
      if (id == Http3SettingsFrame.qpackMaxTableCapacityId) {
        qpackMaxTableCapacity = value;
      } else if (id == Http3SettingsFrame.qpackBlockedStreamsId) {
        qpackBlockedStreams = value;
      } else if (id == Http3SettingsFrame.enableConnectProtocolId) {
        enableConnectProtocol = value != 0;
      } else {
        additionalSettings[id] = value;
      }
    }
    return Http3SettingsFrame(
      qpackMaxTableCapacity: qpackMaxTableCapacity,
      qpackBlockedStreams: qpackBlockedStreams,
      enableConnectProtocol: enableConnectProtocol,
      additionalSettings: additionalSettings,
    );
  }

  static Http3GoawayFrame _decodeGoaway(List<int> payload) {
    final reader = _QuicReader(payload);
    final id = reader.readVarInt();
    if (!reader.isDone) {
      throw const FormatException('GOAWAY frame has trailing data');
    }
    return Http3GoawayFrame(id);
  }
}

class Http3FrameDecoder {
  Http3FrameDecoder({this.streamDataFrames = false});

  final bool streamDataFrames;
  final _header = <int>[];
  int? _frameType;
  int? _remainingPayload;
  BytesBuilder? _payload;

  bool get isAtFrameBoundary =>
      _header.isEmpty && _frameType == null && _remainingPayload == null;

  List<Http3Frame> add(List<int> bytes) {
    final input = bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
    final frames = <Http3Frame>[];
    var offset = 0;
    while (offset < input.length) {
      if (_remainingPayload == null) {
        _header.add(input[offset++]);
        final decoded = _tryReadVarInt();
        if (decoded == null) continue;
        _header.clear();
        if (_frameType == null) {
          _frameType = decoded.value;
          continue;
        }
        _remainingPayload = decoded.value;
        if (_remainingPayload == 0) {
          _finishFrame(frames);
        }
        continue;
      }

      final count = min(_remainingPayload!, input.length - offset);
      final chunk = Uint8List.sublistView(input, offset, offset + count);
      if (_frameType == Http3FrameType.data && streamDataFrames) {
        frames.add(Http3DataFrame._fromBytes(chunk));
      } else if (_isDecodedFrameType(_frameType!)) {
        (_payload ??= BytesBuilder(copy: false)).add(chunk);
      }
      offset += count;
      _remainingPayload = _remainingPayload! - count;
      if (_remainingPayload == 0) _finishFrame(frames);
    }
    return frames;
  }

  QuicDecodedInteger? _tryReadVarInt() {
    try {
      return QuicVariableLengthInteger.decode(_header);
    } on FormatException {
      return null;
    }
  }

  bool _isDecodedFrameType(int type) {
    return type == Http3FrameType.data ||
        type == Http3FrameType.headers ||
        type == Http3FrameType.settings ||
        type == Http3FrameType.goaway;
  }

  void _finishFrame(List<Http3Frame> frames) {
    final type = _frameType!;
    if (type == Http3FrameType.data && streamDataFrames) {
      // DATA chunks are emitted as they arrive.
    } else if (_isDecodedFrameType(type)) {
      final payload = _payload?.takeBytes() ?? Uint8List(0);
      if (type == Http3FrameType.data) {
        frames.add(Http3DataFrame._fromBytes(payload));
      } else if (type == Http3FrameType.headers) {
        frames.add(Http3HeadersFrame(payload));
      } else if (type == Http3FrameType.settings) {
        frames.add(Http3FrameCodec._decodeSettings(payload));
      } else if (type == Http3FrameType.goaway) {
        frames.add(Http3FrameCodec._decodeGoaway(payload));
      }
    }
    _frameType = null;
    _remainingPayload = null;
    _payload = null;
  }
}

/// Minimal QPACK field-section encoder for HTTP/3 requests.
///
/// This emits a header block that does not reference the dynamic table. A
/// complete implementation can replace this type without changing the adapter
/// API because HTTP/3 only sees encoded field sections.
class QpackHeaderBlockEncoder {
  const QpackHeaderBlockEncoder();

  Uint8List encodeHeaders(Map<String, String> headers) {
    final writer = _QuicWriter();
    writer
      ..writeByte(0)
      ..writeByte(0);
    headers.forEach((name, value) {
      _writeLiteralFieldLine(writer, name.toLowerCase(), value);
    });
    return writer.takeBytes();
  }

  void _writeLiteralFieldLine(_QuicWriter writer, String name, String value) {
    final nameBytes = ascii.encode(name);
    final valueBytes = utf8.encode(value);
    _writePrefixedInteger(writer, nameBytes.length, 3, 0x20);
    writer.writeBytes(nameBytes);
    _writePrefixedInteger(writer, valueBytes.length, 7, 0x00);
    writer.writeBytes(valueBytes);
  }

  void _writePrefixedInteger(
    _QuicWriter writer,
    int value,
    int prefixBits,
    int firstByteMask,
  ) {
    final maxPrefixValue = (1 << prefixBits) - 1;
    if (value < maxPrefixValue) {
      writer.writeByte(firstByteMask | value);
      return;
    }
    writer.writeByte(firstByteMask | maxPrefixValue);
    var remaining = value - maxPrefixValue;
    while (remaining >= 128) {
      writer.writeByte((remaining % 128) + 128);
      remaining ~/= 128;
    }
    writer.writeByte(remaining);
  }
}

class QpackHeaderBlockDecoder {
  const QpackHeaderBlockDecoder();

  Map<String, String> decodeHeaders(List<int> headerBlock) {
    final reader = _QuicReader(headerBlock);
    if (reader.remaining < 2) {
      throw const FormatException('Truncated QPACK field section prefix');
    }
    final requiredInsertCount =
        _readPrefixedInteger(reader, reader.readByte(), 8);
    final deltaBase = _readPrefixedInteger(reader, reader.readByte(), 7);
    if (requiredInsertCount != 0 || deltaBase != 0) {
      throw const FormatException('Dynamic QPACK tables are not supported');
    }

    final headers = <String, String>{};
    while (!reader.isDone) {
      final first = reader.readByte();
      if ((first & 0x80) != 0) {
        final isStatic = first & 0x40 != 0;
        if (!isStatic) {
          throw const FormatException('Dynamic QPACK tables are not supported');
        }
        final index = _readPrefixedInteger(reader, first, 6);
        final entry = _staticEntry(index);
        headers[entry.name] = entry.value;
        continue;
      }
      if ((first & 0xc0) == 0x40) {
        final isStatic = first & 0x10 != 0;
        if (!isStatic) {
          throw const FormatException('Dynamic QPACK tables are not supported');
        }
        final nameIndex = _readPrefixedInteger(reader, first, 4);
        final name = _staticEntry(nameIndex).name;
        headers[name] = _readString(reader, reader.readByte(), 7);
        continue;
      }
      if ((first & 0xe0) != 0x20) {
        throw FormatException(
          'Unsupported QPACK field representation 0x${first.toRadixString(16)}',
        );
      }
      final nameIsHuffmanEncoded = first & 0x08 != 0;
      final nameLength = _readPrefixedInteger(reader, first, 3);
      final nameBytes = reader.readBytes(nameLength);
      final name = ascii
          .decode(nameIsHuffmanEncoded ? huffmanDecode(nameBytes) : nameBytes);

      final valueFirst = reader.readByte();
      final value = _readString(reader, valueFirst, 7);
      headers[name] = value;
    }
    return headers;
  }

  String _readString(_QuicReader reader, int first, int prefixBits) {
    final huffman = first & (1 << prefixBits) != 0;
    final length = _readPrefixedInteger(reader, first, prefixBits);
    final bytes = reader.readBytes(length);
    // This small adapter decoder does not yet implement the HPACK/QPACK static
    // Huffman table. Keep the connection usable by preserving the field line
    // shape; exact Huffman-decoded values can be added independently.
    return utf8.decode(huffman ? huffmanDecode(bytes) : bytes);
  }

  int _readPrefixedInteger(_QuicReader reader, int first, int prefixBits) {
    final maxPrefixValue = (1 << prefixBits) - 1;
    var value = first & maxPrefixValue;
    if (value < maxPrefixValue) {
      return value;
    }
    var shift = 0;
    while (true) {
      final next = reader.readByte();
      value += (next & 0x7f) << shift;
      if (next & 0x80 == 0) {
        return value;
      }
      shift += 7;
    }
  }

  _QpackStaticEntry _staticEntry(int index) {
    if (index < 0 || index >= _qpackStaticTable.length) {
      throw FormatException('Invalid QPACK static table index $index');
    }
    return _qpackStaticTable[index];
  }
}

class _QpackStaticEntry {
  const _QpackStaticEntry(this.name, this.value);

  final String name;
  final String value;
}

const _qpackStaticTable = <_QpackStaticEntry>[
  _QpackStaticEntry(':authority', ''),
  _QpackStaticEntry(':path', '/'),
  _QpackStaticEntry('age', '0'),
  _QpackStaticEntry('content-disposition', ''),
  _QpackStaticEntry('content-length', '0'),
  _QpackStaticEntry('cookie', ''),
  _QpackStaticEntry('date', ''),
  _QpackStaticEntry('etag', ''),
  _QpackStaticEntry('if-modified-since', ''),
  _QpackStaticEntry('if-none-match', ''),
  _QpackStaticEntry('last-modified', ''),
  _QpackStaticEntry('link', ''),
  _QpackStaticEntry('location', ''),
  _QpackStaticEntry('referer', ''),
  _QpackStaticEntry('set-cookie', ''),
  _QpackStaticEntry(':method', 'CONNECT'),
  _QpackStaticEntry(':method', 'DELETE'),
  _QpackStaticEntry(':method', 'GET'),
  _QpackStaticEntry(':method', 'HEAD'),
  _QpackStaticEntry(':method', 'OPTIONS'),
  _QpackStaticEntry(':method', 'POST'),
  _QpackStaticEntry(':method', 'PUT'),
  _QpackStaticEntry(':scheme', 'http'),
  _QpackStaticEntry(':scheme', 'https'),
  _QpackStaticEntry(':status', '103'),
  _QpackStaticEntry(':status', '200'),
  _QpackStaticEntry(':status', '304'),
  _QpackStaticEntry(':status', '404'),
  _QpackStaticEntry(':status', '503'),
  _QpackStaticEntry('accept', '*/*'),
  _QpackStaticEntry('accept', 'application/dns-message'),
  _QpackStaticEntry('accept-encoding', 'gzip, deflate, br'),
  _QpackStaticEntry('accept-ranges', 'bytes'),
  _QpackStaticEntry('access-control-allow-headers', 'cache-control'),
  _QpackStaticEntry('access-control-allow-headers', 'content-type'),
  _QpackStaticEntry('access-control-allow-origin', '*'),
  _QpackStaticEntry('cache-control', 'max-age=0'),
  _QpackStaticEntry('cache-control', 'max-age=2592000'),
  _QpackStaticEntry('cache-control', 'max-age=604800'),
  _QpackStaticEntry('cache-control', 'no-cache'),
  _QpackStaticEntry('cache-control', 'no-store'),
  _QpackStaticEntry('cache-control', 'public, max-age=31536000'),
  _QpackStaticEntry('content-encoding', 'br'),
  _QpackStaticEntry('content-encoding', 'gzip'),
  _QpackStaticEntry('content-type', 'application/dns-message'),
  _QpackStaticEntry('content-type', 'application/javascript'),
  _QpackStaticEntry('content-type', 'application/json'),
  _QpackStaticEntry('content-type', 'application/x-www-form-urlencoded'),
  _QpackStaticEntry('content-type', 'image/gif'),
  _QpackStaticEntry('content-type', 'image/jpeg'),
  _QpackStaticEntry('content-type', 'image/png'),
  _QpackStaticEntry('content-type', 'text/css'),
  _QpackStaticEntry('content-type', 'text/html; charset=utf-8'),
  _QpackStaticEntry('content-type', 'text/plain'),
  _QpackStaticEntry('content-type', 'text/plain;charset=utf-8'),
  _QpackStaticEntry('range', 'bytes=0-'),
  _QpackStaticEntry('strict-transport-security', 'max-age=31536000'),
  _QpackStaticEntry(
      'strict-transport-security', 'max-age=31536000; includesubdomains'),
  _QpackStaticEntry('strict-transport-security',
      'max-age=31536000; includesubdomains; preload'),
  _QpackStaticEntry('vary', 'accept-encoding'),
  _QpackStaticEntry('vary', 'origin'),
  _QpackStaticEntry('x-content-type-options', 'nosniff'),
  _QpackStaticEntry('x-xss-protection', '1; mode=block'),
  _QpackStaticEntry(':status', '100'),
  _QpackStaticEntry(':status', '204'),
  _QpackStaticEntry(':status', '206'),
  _QpackStaticEntry(':status', '302'),
  _QpackStaticEntry(':status', '400'),
  _QpackStaticEntry(':status', '403'),
  _QpackStaticEntry(':status', '421'),
  _QpackStaticEntry(':status', '425'),
  _QpackStaticEntry(':status', '500'),
  _QpackStaticEntry('accept-language', ''),
  _QpackStaticEntry('access-control-allow-credentials', 'FALSE'),
  _QpackStaticEntry('access-control-allow-credentials', 'TRUE'),
  _QpackStaticEntry('access-control-allow-headers', '*'),
  _QpackStaticEntry('access-control-allow-methods', 'get'),
  _QpackStaticEntry('access-control-allow-methods', 'get, post, options'),
  _QpackStaticEntry('access-control-allow-methods', 'options'),
  _QpackStaticEntry('access-control-expose-headers', 'content-length'),
  _QpackStaticEntry('access-control-request-headers', 'content-type'),
  _QpackStaticEntry('access-control-request-method', 'get'),
  _QpackStaticEntry('access-control-request-method', 'post'),
  _QpackStaticEntry('alt-svc', 'clear'),
  _QpackStaticEntry('authorization', ''),
  _QpackStaticEntry('content-security-policy',
      "script-src 'none'; object-src 'none'; base-uri 'none'"),
  _QpackStaticEntry('early-data', '1'),
  _QpackStaticEntry('expect-ct', ''),
  _QpackStaticEntry('forwarded', ''),
  _QpackStaticEntry('if-range', ''),
  _QpackStaticEntry('origin', ''),
  _QpackStaticEntry('purpose', 'prefetch'),
  _QpackStaticEntry('server', ''),
  _QpackStaticEntry('timing-allow-origin', '*'),
  _QpackStaticEntry('upgrade-insecure-requests', '1'),
  _QpackStaticEntry('user-agent', ''),
  _QpackStaticEntry('x-forwarded-for', ''),
  _QpackStaticEntry('x-frame-options', 'deny'),
  _QpackStaticEntry('x-frame-options', 'sameorigin'),
];

class Http3RequestWriter {
  const Http3RequestWriter({
    this.headerEncoder = const QpackHeaderBlockEncoder(),
  });

  final QpackHeaderBlockEncoder headerEncoder;

  Map<String, String> requestHeaders(RequestOptions options) {
    final uri = options.uri;
    var path = uri.path.isEmpty ? '/' : uri.path;
    if (uri.query.isNotEmpty) {
      path = '$path?${uri.query}';
    }
    final headers = <String, String>{
      ':method': options.method,
      ':scheme': uri.scheme,
      ':authority': uri.host,
      ':path': path,
    };
    options.headers.forEach((key, value) {
      headers[key] = value?.toString() ?? '';
    });
    return headers;
  }

  Uint8List encodeRequestHeaders(RequestOptions options) {
    return Http3HeadersFrame(
      headerEncoder.encodeHeaders(requestHeaders(options)),
    ).encode();
  }
}
