part of '../http3_adapter.dart';

/// RFC 9000 variable-length integer codec.
///
/// QUIC uses the two most significant bits of the first byte to encode the
/// integer length: 1, 2, 4, or 8 bytes.
class QuicVariableLengthInteger {
  static const int maxValue = 0x3fffffffffffffff;

  static int encodingLength(int value) {
    if (value < 0 || value > maxValue) {
      throw RangeError.range(value, 0, maxValue, 'value');
    }
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;
    return 8;
  }

  static Uint8List encode(int value) {
    final length = encodingLength(value);
    final bytes = Uint8List(length);
    var encoded = value;
    if (length == 2) {
      encoded |= 0x4000;
    } else if (length == 4) {
      encoded |= 0x80000000;
    } else if (length == 8) {
      encoded |= 0xc000000000000000;
    }
    for (var i = length - 1; i >= 0; i--) {
      bytes[i] = encoded & 0xff;
      encoded >>= 8;
    }
    return bytes;
  }

  static QuicDecodedInteger decode(List<int> bytes, [int offset = 0]) {
    if (offset >= bytes.length) {
      throw const FormatException('Missing QUIC variable-length integer');
    }
    final first = bytes[offset];
    final marker = first >> 6;
    final length = 1 << marker;
    if (offset + length > bytes.length) {
      throw const FormatException('Truncated QUIC variable-length integer');
    }
    var value = first & 0x3f;
    for (var i = 1; i < length; i++) {
      value = (value << 8) | bytes[offset + i];
    }
    return QuicDecodedInteger(value, length);
  }
}

class QuicDecodedInteger {
  const QuicDecodedInteger(this.value, this.bytesRead);

  final int value;
  final int bytesRead;
}

class _QuicWriter {
  final BytesBuilder _builder = BytesBuilder(copy: false);

  int get length => _builder.length;

  void writeByte(int value) {
    _builder.addByte(value & 0xff);
  }

  void writeUint32(int value) {
    _builder.add([
      (value >> 24) & 0xff,
      (value >> 16) & 0xff,
      (value >> 8) & 0xff,
      value & 0xff,
    ]);
  }

  void writeVarInt(int value) {
    _builder.add(QuicVariableLengthInteger.encode(value));
  }

  void writeBytes(List<int> bytes) {
    _builder.add(bytes);
  }

  Uint8List takeBytes() => _builder.takeBytes();
}

class _QuicReader {
  _QuicReader(this._bytes);

  final List<int> _bytes;
  int offset = 0;

  int get remaining => _bytes.length - offset;

  bool get isDone => offset == _bytes.length;

  int readByte() {
    if (remaining < 1) {
      throw const FormatException('Unexpected end of QUIC buffer');
    }
    return _bytes[offset++];
  }

  int readUint32() {
    if (remaining < 4) {
      throw const FormatException('Unexpected end of QUIC buffer');
    }
    final value = (_bytes[offset] << 24) |
        (_bytes[offset + 1] << 16) |
        (_bytes[offset + 2] << 8) |
        _bytes[offset + 3];
    offset += 4;
    return value;
  }

  int readVarInt() {
    final decoded = QuicVariableLengthInteger.decode(_bytes, offset);
    offset += decoded.bytesRead;
    return decoded.value;
  }

  Uint8List readBytes(int length) {
    if (length < 0 || remaining < length) {
      throw const FormatException('Unexpected end of QUIC buffer');
    }
    final start = offset;
    offset += length;
    return Uint8List.fromList(_bytes.sublist(start, offset));
  }
}

enum QuicEncryptionLevel {
  initial,
  zeroRtt,
  handshake,
  oneRtt,
}

enum QuicLongHeaderPacketType {
  initial,
  zeroRtt,
  handshake,
  retry,
}

class QuicConnectionId {
  QuicConnectionId(List<int> bytes) : bytes = Uint8List.fromList(bytes) {
    if (bytes.length > 20) {
      throw RangeError.range(bytes.length, 0, 20, 'bytes.length');
    }
  }

  factory QuicConnectionId.random([int length = 8]) {
    if (length < 0 || length > 20) {
      throw RangeError.range(length, 0, 20, 'length');
    }
    final random = Random.secure();
    return QuicConnectionId(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }

  final Uint8List bytes;

  @override
  String toString() =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

abstract class QuicFrame {
  int get type;

  void encodeTo(_QuicWriter writer);

  Uint8List encode() {
    final writer = _QuicWriter();
    encodeTo(writer);
    return writer.takeBytes();
  }
}

class QuicCryptoFrame extends QuicFrame {
  QuicCryptoFrame(this.offset, List<int> data)
      : data = Uint8List.fromList(data);

  @override
  int get type => 0x06;

  final int offset;
  final Uint8List data;

  @override
  void encodeTo(_QuicWriter writer) {
    writer
      ..writeVarInt(type)
      ..writeVarInt(offset)
      ..writeVarInt(data.length)
      ..writeBytes(data);
  }
}

class QuicStreamFrame extends QuicFrame {
  QuicStreamFrame({
    required this.streamId,
    this.offset = 0,
    required List<int> data,
    this.fin = false,
  }) : data = Uint8List.fromList(data);

  @override
  int get type =>
      0x08 | (offset > 0 ? 0x04 : 0x00) | 0x02 | (fin ? 0x01 : 0x00);

  final int streamId;
  final int offset;
  final Uint8List data;
  final bool fin;

  @override
  void encodeTo(_QuicWriter writer) {
    writer
      ..writeVarInt(type)
      ..writeVarInt(streamId);
    if (offset > 0) {
      writer.writeVarInt(offset);
    }
    writer
      ..writeVarInt(data.length)
      ..writeBytes(data);
  }
}

class QuicAckFrame extends QuicFrame {
  QuicAckFrame({
    required this.largestAcknowledged,
    required this.ackDelay,
    this.ackRangeCount = 0,
    this.firstAckRange = 0,
  });

  @override
  int get type => 0x02;

  final int largestAcknowledged;
  final int ackDelay;
  final int ackRangeCount;
  final int firstAckRange;

  @override
  void encodeTo(_QuicWriter writer) {
    writer
      ..writeVarInt(type)
      ..writeVarInt(largestAcknowledged)
      ..writeVarInt(ackDelay)
      ..writeVarInt(ackRangeCount)
      ..writeVarInt(firstAckRange);
  }
}

class QuicFrameCodec {
  static List<QuicFrame> decodeAll(List<int> bytes) {
    final reader = _QuicReader(bytes);
    final frames = <QuicFrame>[];
    while (!reader.isDone) {
      frames.add(_decodeOne(reader));
    }
    return frames;
  }

  static QuicFrame _decodeOne(_QuicReader reader) {
    final type = reader.readVarInt();
    if (type == 0x06) {
      final offset = reader.readVarInt();
      final length = reader.readVarInt();
      return QuicCryptoFrame(offset, reader.readBytes(length));
    }
    if (type & 0xf8 == 0x08) {
      final streamId = reader.readVarInt();
      final hasOffset = type & 0x04 != 0;
      final hasLength = type & 0x02 != 0;
      final offset = hasOffset ? reader.readVarInt() : 0;
      final length = hasLength ? reader.readVarInt() : reader.remaining;
      return QuicStreamFrame(
        streamId: streamId,
        offset: offset,
        data: reader.readBytes(length),
        fin: type & 0x01 != 0,
      );
    }
    if (type == 0x02) {
      return QuicAckFrame(
        largestAcknowledged: reader.readVarInt(),
        ackDelay: reader.readVarInt(),
        ackRangeCount: reader.readVarInt(),
        firstAckRange: reader.readVarInt(),
      );
    }
    throw FormatException(
        'Unsupported QUIC frame type 0x${type.toRadixString(16)}');
  }
}

class QuicTransportParameters {
  QuicTransportParameters({
    this.initialMaxData = 1024 * 1024,
    this.initialMaxStreamDataBidiLocal = 512 * 1024,
    this.initialMaxStreamDataBidiRemote = 512 * 1024,
    this.initialMaxStreamDataUni = 512 * 1024,
    this.initialMaxStreamsBidi = 100,
    this.initialMaxStreamsUni = 100,
    this.maxIdleTimeout = const Duration(seconds: 30),
    this.maxUdpPayloadSize = 1200,
    this.activeConnectionIdLimit = 2,
    this.initialSourceConnectionId,
  });

  final int initialMaxData;
  final int initialMaxStreamDataBidiLocal;
  final int initialMaxStreamDataBidiRemote;
  final int initialMaxStreamDataUni;
  final int initialMaxStreamsBidi;
  final int initialMaxStreamsUni;
  final Duration maxIdleTimeout;
  final int maxUdpPayloadSize;
  final int activeConnectionIdLimit;
  final Uint8List? initialSourceConnectionId;

  Uint8List encode() {
    final writer = _QuicWriter();
    _writeParameter(writer, 0x01, maxIdleTimeout.inMilliseconds);
    _writeParameter(writer, 0x03, maxUdpPayloadSize);
    _writeParameter(writer, 0x04, initialMaxData);
    _writeParameter(writer, 0x05, initialMaxStreamDataBidiLocal);
    _writeParameter(writer, 0x06, initialMaxStreamDataBidiRemote);
    _writeParameter(writer, 0x07, initialMaxStreamDataUni);
    _writeParameter(writer, 0x08, initialMaxStreamsBidi);
    _writeParameter(writer, 0x09, initialMaxStreamsUni);
    _writeParameter(writer, 0x0e, activeConnectionIdLimit);
    // 14, 1, 2, 15, 8, 167, 189, 73, 125, 240, 37, 111, 13
    final initialSourceConnectionId = this.initialSourceConnectionId;
    if (initialSourceConnectionId != null) {
      _writeBytesParameter(writer, 0x0f, initialSourceConnectionId);
    }
    return writer.takeBytes();
  }

  static void _writeParameter(_QuicWriter writer, int id, int value) {
    final encodedValue = QuicVariableLengthInteger.encode(value);
    writer
      ..writeVarInt(id)
      ..writeVarInt(encodedValue.length)
      ..writeBytes(encodedValue);
  }

  static void _writeBytesParameter(
      _QuicWriter writer, int id, List<int> value) {
    writer
      ..writeVarInt(id)
      ..writeVarInt(value.length)
      ..writeBytes(value);
  }

  @override
  String toString() => 'QuicTransportParameters(${{
    'initialMaxData': initialMaxData,
    'initialMaxStreamDataBidiLocal': initialMaxStreamDataBidiLocal,
    'initialMaxStreamDataBidiRemote': initialMaxStreamDataBidiRemote,
    'initialMaxStreamDataUni': initialMaxStreamDataUni,
    'initialMaxStreamsBidi': initialMaxStreamsBidi,
    'initialMaxStreamsUni': initialMaxStreamsUni,
    'maxIdleTimeout': maxIdleTimeout,
    'maxUdpPayloadSize': maxUdpPayloadSize,
    'activeConnectionIdLimit': activeConnectionIdLimit,
    'initialSourceConnectionId': initialSourceConnectionId,
  }})';
}

class QuicInitialPacket {
  QuicInitialPacket({
    this.version = 0x00000001,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    this.token = const <int>[],
    this.packetNumber = 0,
    required List<int> payload,
  }) : payload = Uint8List.fromList(payload);

  final int version;
  final QuicConnectionId destinationConnectionId;
  final QuicConnectionId sourceConnectionId;
  final List<int> token;
  final int packetNumber;
  final Uint8List payload;
}

class QuicPacketCodec {
  static Uint8List encodeInitial(QuicInitialPacket packet) {
    final packetNumberLength = _packetNumberLength(packet.packetNumber);
    final writer = _QuicWriter();
    writer
      ..writeByte(0xc0 | (packetNumberLength - 1))
      ..writeUint32(packet.version)
      ..writeByte(packet.destinationConnectionId.bytes.length)
      ..writeBytes(packet.destinationConnectionId.bytes)
      ..writeByte(packet.sourceConnectionId.bytes.length)
      ..writeBytes(packet.sourceConnectionId.bytes)
      ..writeVarInt(packet.token.length)
      ..writeBytes(packet.token)
      ..writeVarInt(packetNumberLength + packet.payload.length);
    _writePacketNumber(writer, packet.packetNumber, packetNumberLength);
    writer.writeBytes(packet.payload);
    return writer.takeBytes();
  }

  static QuicInitialPacket decodeInitial(List<int> bytes) {
    final reader = _QuicReader(bytes);
    final first = reader.readByte();
    if (first & 0x80 == 0 || first & 0x40 == 0) {
      throw const FormatException('Not a QUIC long-header packet');
    }
    final packetType = (first & 0x30) >> 4;
    if (packetType != 0) {
      throw const FormatException('Not a QUIC Initial packet');
    }
    final packetNumberLength = (first & 0x03) + 1;
    final version = reader.readUint32();
    final dcid = QuicConnectionId(reader.readBytes(reader.readByte()));
    final scid = QuicConnectionId(reader.readBytes(reader.readByte()));
    final tokenLength = reader.readVarInt();
    final token = reader.readBytes(tokenLength);
    final payloadAndPacketNumberLength = reader.readVarInt();
    if (payloadAndPacketNumberLength < packetNumberLength) {
      throw const FormatException('Invalid QUIC Initial length');
    }
    var packetNumber = 0;
    for (var i = 0; i < packetNumberLength; i++) {
      packetNumber = (packetNumber << 8) | reader.readByte();
    }
    return QuicInitialPacket(
      version: version,
      destinationConnectionId: dcid,
      sourceConnectionId: scid,
      token: token,
      packetNumber: packetNumber,
      payload:
          reader.readBytes(payloadAndPacketNumberLength - packetNumberLength),
    );
  }

  static int _packetNumberLength(int packetNumber) {
    if (packetNumber < 0) {
      throw RangeError.range(packetNumber, 0, null, 'packetNumber');
    }
    if (packetNumber <= 0xff) return 1;
    if (packetNumber <= 0xffff) return 2;
    if (packetNumber <= 0xffffff) return 3;
    return 4;
  }

  static void _writePacketNumber(
      _QuicWriter writer, int packetNumber, int length) {
    for (var i = length - 1; i >= 0; i--) {
      writer.writeByte(packetNumber >> (8 * i));
    }
  }
}
