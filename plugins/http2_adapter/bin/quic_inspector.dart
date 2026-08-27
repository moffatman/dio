import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';

const _defaultPort = 4433;
const _defaultSslLibrary = '/Users/callum/Code/boringssl/libssl.dylib';
const _defaultCryptoLibrary = '/Users/callum/Code/boringssl/libcrypto.dylib';
const _quicVersion1 = 0x00000001;
const _tlsAes128GcmSha256 = 0x03001301;
const _tlsAes256GcmSha384 = 0x03001302;
const _tls13Version = 0x0304;
const _sslErrorWantRead = 2;
const _sslErrorWantWrite = 3;
const _sslFiletypePem = 1;
const _sslTlsextErrOk = 0;
const _sslTlsextErrAlertFatal = 2;
const _quicPacketTypeInitial = 0;
const _quicPacketTypeHandshake = 2;
const _quicMinInitialDatagramSize = 1200;
const _quicMaxDatagramPayloadSize = 1200;
const _quicTagLength = 16;
const _h3Alpn = 'h3';
const _preferredServerConnectionId = <int>[
  0xe0,
  0xe1,
  0xe2,
  0xe3,
  0xe4,
  0xe5,
  0xe6,
  0xe7,
];
const _preferredStatelessResetToken = <int>[
  0xf0,
  0xf1,
  0xf2,
  0xf3,
  0xf4,
  0xf5,
  0xf6,
  0xf7,
  0xf8,
  0xf9,
  0xfa,
  0xfb,
  0xfc,
  0xfd,
  0xfe,
  0xff,
];
const _quicInitialSalt = <int>[
  0x38,
  0x76,
  0x2c,
  0xf7,
  0xf5,
  0x59,
  0x34,
  0xb3,
  0x4d,
  0x17,
  0x9a,
  0xe6,
  0xa4,
  0xc8,
  0x0c,
  0xad,
  0xcc,
  0xbb,
  0x7f,
  0x0a,
];

const _embeddedLocalhostCertPem = '''
-----BEGIN CERTIFICATE-----
MIIBmTCCAT+gAwIBAgIUHCdWKhGpHKGwbRFrdQF0r/GZZpYwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwMTAwNDExN1oXDTM2MDUyOTAw
NDExN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEbz0OS065Q0aFAb3C4xAkffxpfk9OabOsEwjSO/gAdnhJrNWYhtC3gkTI
PfFVZ5HI0rlcHF029zCW032Qu89F7qNvMG0wHQYDVR0OBBYEFCFhr+KFo7rPrrHf
sBYbKIwfpl+JMB8GA1UdIwQYMBaAFCFhr+KFo7rPrrHfsBYbKIwfpl+JMA8GA1Ud
EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49
BAMCA0gAMEUCIGCiWu+7PTD8aTcU5p6rOF/wptgExR1h+LByjzs9Cg0kAiEA6aeP
b5+WMSoWmewyYCpjKcG6i0Nu0k8s8OPzuUgRZFs=
-----END CERTIFICATE-----
''';

const _embeddedLocalhostKeyPem = '''
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEL1v46hgfaG5+Ktd3CdLnGLxqwrJoMh0If1P4IjWhJioAoGCCqGSM49
AwEHoUQDQgAEbz0OS065Q0aFAb3C4xAkffxpfk9OabOsEwjSO/gAdnhJrNWYhtC3
gkTIPfFVZ5HI0rlcHF029zCW032Qu89F7g==
-----END EC PRIVATE KEY-----
''';

Future<void> main(List<String> args) async {
  final options = _InspectorOptions.parse(args);
  final certificateFile = options.certificateFile ??
      await _writeEmbeddedPem('cert.pem', _embeddedLocalhostCertPem);
  final privateKeyFile = options.privateKeyFile ??
      await _writeEmbeddedPem('key.pem', _embeddedLocalhostKeyPem);
  final crypto = _BoringSslCrypto(
    sslLibraryPath: options.sslLibraryPath,
    cryptoLibraryPath: options.cryptoLibraryPath,
  );
  final socket = await RawDatagramSocket.bind(
    options.listenIpv6
        ? InternetAddress.loopbackIPv6
        : InternetAddress.loopbackIPv4,
    options.port,
  );
  final preferredSocket = options.preferredAddress
      ? await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0)
      : null;
  final server = _QuicInspectorServer(
    crypto: crypto,
    certificateFile: certificateFile,
    privateKeyFile: privateKeyFile,
    initialMaxData: options.initialMaxData,
    initialMaxStreamData: options.initialMaxStreamData,
    maxIdleTimeout: options.maxIdleTimeout,
    terminateFirstClientStream: options.terminateFirstClientStream,
    completeResponseResetNoError: options.completeResponseResetNoError,
    keyUpdateAfterHandshake: options.keyUpdateAfterHandshake,
    closeAfterHandshake: options.closeAfterHandshake,
    probeClientClose: options.probeClientClose,
    versionNegotiation: options.versionNegotiation,
    versionNegotiationIncludesV1: options.versionNegotiationIncludesV1,
    statelessResetAfterHandshake: options.statelessResetAfterHandshake,
    rotateConnectionId: options.rotateConnectionId,
    pathChallengeAfterHandshake: options.pathChallengeAfterHandshake,
    newToken: options.newToken,
    retry: options.retry,
    rejectResumedEarlyData: options.rejectResumedEarlyData,
    dynamicQpackResponse: options.dynamicQpackResponse,
    redirectLocation: options.redirectLocation,
    responseAltSvc: options.responseAltSvc,
    goawayAfterFirstRequest: options.goawayAfterFirstRequest,
    rejectFirstRequestWithGoaway: options.rejectFirstRequestWithGoaway,
    echoApplicationData: options.echoApplicationData,
    sendFlowControlViolation: options.sendFlowControlViolation,
    preferredAddressPort: preferredSocket?.port,
  );
  print('QUIC inspector listening on ${socket.address.address}:${socket.port}');
  if (preferredSocket != null) {
    print(
      'QUIC inspector preferred address '
      '127.0.0.1:${preferredSocket.port}',
    );
  }
  print('Using ${options.sslLibraryPath}');
  print('Using certificate $certificateFile');
  print('Send a QUIC client at https://localhost:${socket.port}/');

  var droppedFirstClientDatagram = false;
  void listen(RawDatagramSocket receivingSocket) {
    receivingSocket.writeEventsEnabled = false;
    receivingSocket.listen((event) {
      if (event == RawSocketEvent.write) {
        server.flushWrites(receivingSocket);
        return;
      }
      if (event != RawSocketEvent.read) return;
      while (true) {
        final datagram = receivingSocket.receive();
        if (datagram == null) break;
        if (identical(receivingSocket, socket) &&
            options.dropFirstClientDatagram &&
            !droppedFirstClientDatagram) {
          droppedFirstClientDatagram = true;
          print('dropped first client datagram length=${datagram.data.length}');
          continue;
        }
        if (options.quiet) {
          runZoned(
            () => _inspectDatagram(crypto, server, receivingSocket, datagram),
            zoneSpecification: ZoneSpecification(
              print: (_, __, ___, ____) {},
            ),
          );
        } else {
          _inspectDatagram(crypto, server, receivingSocket, datagram);
        }
      }
    });
  }

  listen(socket);
  if (preferredSocket != null) listen(preferredSocket);

  await Completer<void>().future;
}

Future<String> _writeEmbeddedPem(String name, String contents) async {
  final directory = await Directory.systemTemp.createTemp('quic-inspector-');
  final file = File('${directory.path}/$name');
  await file.writeAsString(contents);
  return file.path;
}

void _inspectDatagram(
  _BoringSslCrypto crypto,
  _QuicInspectorServer server,
  RawDatagramSocket receivingSocket,
  Datagram datagram,
) {
  final bytes = datagram.data;
  print('');
  print('datagram from ${datagram.address.address}:${datagram.port}');
  print('udp.length=${bytes.length} '
      'prefix=${_formatBytes(bytes.take(12).toList())}');
  if (bytes.length < 1200) {
    print('WARN client Initial datagrams usually need UDP payload >= 1200');
  }

  var offset = 0;
  var packetIndex = 0;
  while (offset < bytes.length) {
    final result = _inspectPacket(
      crypto,
      server,
      bytes,
      offset,
      packetIndex,
    );
    final consumed = result.consumed;
    if (consumed <= 0) break;
    if (result.packet != null) {
      server.handlePacket(receivingSocket, datagram, result.packet!);
    }
    offset += consumed;
    packetIndex++;
  }
}

_PacketInspection _inspectPacket(
  _BoringSslCrypto crypto,
  _QuicInspectorServer server,
  Uint8List datagram,
  int packetStart,
  int packetIndex,
) {
  final first = datagram[packetStart];
  final isLongHeader = (first & 0x80) != 0;
  final fixedBit = (first & 0x40) != 0;
  print('packet[$packetIndex] start=$packetStart first=0x${_hexByte(first)} '
      'long=$isLongHeader fixed=$fixedBit');
  if (!fixedBit) {
    print('  ERROR fixed bit is not set');
  }
  if (!isLongHeader) {
    return _inspectShortHeaderPacket(
      crypto,
      server,
      datagram,
      packetStart,
    );
  }

  var cursor = packetStart + 1;
  if (cursor + 4 > datagram.length) {
    print('  ERROR truncated version');
    return _PacketInspection(0, null);
  }
  final version = _readUint32(datagram, cursor);
  cursor += 4;
  final packetType = (first & 0x30) >> 4;
  print('  version=0x${version.toRadixString(16).padLeft(8, '0')} '
      'type=${_longPacketTypeName(packetType)}');
  if (version != _quicVersion1) {
    print('  unsupported version');
    return _PacketInspection(datagram.length - packetStart, null);
  }

  if (cursor >= datagram.length) {
    print('  ERROR truncated dcid length');
    return _PacketInspection(0, null);
  }
  final dcidLen = datagram[cursor++];
  if (cursor + dcidLen > datagram.length) {
    print('  ERROR truncated dcid');
    return _PacketInspection(0, null);
  }
  final dcid = Uint8List.fromList(datagram.sublist(cursor, cursor + dcidLen));
  cursor += dcidLen;

  if (cursor >= datagram.length) {
    print('  ERROR truncated scid length');
    return _PacketInspection(0, null);
  }
  final scidLen = datagram[cursor++];
  if (cursor + scidLen > datagram.length) {
    print('  ERROR truncated scid');
    return _PacketInspection(0, null);
  }
  final scid = Uint8List.fromList(datagram.sublist(cursor, cursor + scidLen));
  cursor += scidLen;

  print('  dcid[$dcidLen]=${_hex(dcid)} scid[$scidLen]=${_hex(scid)}');

  var initialToken = Uint8List(0);
  if (packetType == 0) {
    final tokenLen = _readVarInt(datagram, cursor);
    if (tokenLen == null) {
      print('  ERROR truncated token length');
      return _PacketInspection(0, null);
    }
    cursor = tokenLen.nextOffset;
    if (cursor + tokenLen.value > datagram.length) {
      print('  ERROR truncated token');
      return _PacketInspection(0, null);
    }
    print('  token.length=${tokenLen.value}');
    initialToken = Uint8List.fromList(
      datagram.sublist(cursor, cursor + tokenLen.value),
    );
    cursor += tokenLen.value;
  }

  final packetLength = _readVarInt(datagram, cursor);
  if (packetLength == null) {
    print('  ERROR truncated packet length');
    return _PacketInspection(0, null);
  }
  cursor = packetLength.nextOffset;
  final pnOffset = cursor;
  final packetEnd = pnOffset + packetLength.value;
  print('  lengthField=${packetLength.value} pnOffset=$pnOffset '
      'packetEnd=$packetEnd');
  if (packetEnd > datagram.length) {
    print('  ERROR packet length extends past datagram');
    return _PacketInspection(datagram.length - packetStart, null);
  }
  if (pnOffset + 20 > packetEnd) {
    print('  ERROR not enough bytes for header-protection sample');
    return _PacketInspection(packetEnd - packetStart, null);
  }

  final protection = switch (packetType) {
    _quicPacketTypeInitial => _PacketProtection(
        level: _QuicEncryptionLevel.initial,
        keys: crypto.initialKeys(dcid, client: true),
        cipherId: _tlsAes128GcmSha256,
      ),
    _quicPacketTypeHandshake => server.protectionForIncomingHandshake(dcid),
    1 => server.protectionForIncomingEarlyData(dcid),
    _ => null,
  };
  if (protection == null) {
    print('  long-header packet keys are not available');
    return _PacketInspection(packetEnd - packetStart, null);
  }

  final unprotected =
      Uint8List.fromList(datagram.sublist(packetStart, packetEnd));
  final sampleOffset = pnOffset - packetStart + 4;
  final sample = Uint8List.fromList(
    unprotected.sublist(sampleOffset, sampleOffset + 16),
  );
  final mask = crypto.aesMask(protection.keys.hp, sample);
  unprotected[0] ^= mask[0] & 0x0f;
  final pnLength = (unprotected[0] & 0x03) + 1;
  for (var i = 0; i < pnLength; i++) {
    unprotected[pnOffset - packetStart + i] ^= mask[i + 1];
  }

  final packetNumber = _readPacketNumber(
    unprotected,
    pnOffset - packetStart,
    pnLength,
  );
  final payloadOffset = pnOffset + pnLength;
  final ciphertextLength = packetEnd - payloadOffset;
  print('  unprotectedFirst=0x${_hexByte(unprotected[0])} '
      'pnLength=$pnLength pn=$packetNumber ciphertext=$ciphertextLength');

  final aad = Uint8List.fromList(
    unprotected.sublist(0, payloadOffset - packetStart),
  );
  final ciphertext =
      Uint8List.fromList(datagram.sublist(payloadOffset, packetEnd));
  final plaintext = crypto.open(
    key: protection.keys.key,
    nonce: protection.keys.nonce(packetNumber),
    ciphertext: ciphertext,
    aad: aad,
    cipherId: protection.cipherId,
  );
  if (plaintext == null) {
    print('  ERROR AEAD open failed');
    return _PacketInspection(packetEnd - packetStart, null);
  }
  print('  plaintext.length=${plaintext.length} '
      'padding.bytes=${_countPaddingBytes(plaintext)}');
  final frames = _parseFrames(plaintext);
  return _PacketInspection(
    packetEnd - packetStart,
    _InspectedPacket(
      type: packetType,
      level: protection.level,
      destinationConnectionId: dcid,
      sourceConnectionId: scid,
      packetNumber: packetNumber,
      cryptoFrames: frames.cryptoFrames,
      blockedFrames: frames.blockedFrames,
      streamFrames: frames.streamFrames,
      pathChallenges: frames.pathChallenges,
      datagrams: frames.datagrams,
      connectionClose: frames.connectionClose,
      initialToken: initialToken,
    ),
  );
}

_PacketInspection _inspectShortHeaderPacket(
  _BoringSslCrypto crypto,
  _QuicInspectorServer server,
  Uint8List datagram,
  int packetStart,
) {
  final match = server.shortHeaderProtection(datagram, packetStart + 1);
  if (match == null) {
    print('  short header packet; inspector does not have matching 1-RTT keys');
    return _PacketInspection(datagram.length - packetStart, null);
  }

  final packetEnd = datagram.length;
  final pnOffset = packetStart + 1 + match.destinationConnectionId.length;
  if (pnOffset + 20 > packetEnd) {
    print('  ERROR not enough bytes for short-header protection sample');
    return _PacketInspection(packetEnd - packetStart, null);
  }

  final unprotected =
      Uint8List.fromList(datagram.sublist(packetStart, packetEnd));
  final sampleOffset = pnOffset - packetStart + 4;
  final sample = Uint8List.fromList(
    unprotected.sublist(sampleOffset, sampleOffset + 16),
  );
  final mask = crypto.aesMask(match.protection.keys.hp, sample);
  unprotected[0] ^= mask[0] & 0x1f;
  final pnLength = (unprotected[0] & 0x03) + 1;
  for (var i = 0; i < pnLength; i++) {
    unprotected[pnOffset - packetStart + i] ^= mask[i + 1];
  }

  final packetNumber = _readPacketNumber(
    unprotected,
    pnOffset - packetStart,
    pnLength,
  );
  final payloadOffset = pnOffset + pnLength;
  final ciphertextLength = packetEnd - payloadOffset;
  print(
      '  short dcid[${match.destinationConnectionId.length}]=${_hex(match.destinationConnectionId)} '
      'unprotectedFirst=0x${_hexByte(unprotected[0])} '
      'keyPhase=${(unprotected[0] & 0x04) == 0 ? 0 : 1} '
      'pnLength=$pnLength pn=$packetNumber ciphertext=$ciphertextLength');

  final aad = Uint8List.fromList(
    unprotected.sublist(0, payloadOffset - packetStart),
  );
  final ciphertext =
      Uint8List.fromList(datagram.sublist(payloadOffset, packetEnd));
  final plaintext = crypto.open(
    key: match.protection.keys.key,
    nonce: match.protection.keys.nonce(packetNumber),
    ciphertext: ciphertext,
    aad: aad,
    cipherId: match.protection.cipherId,
  );
  if (plaintext == null) {
    print('  ERROR AEAD open failed');
    return _PacketInspection(packetEnd - packetStart, null);
  }

  print('  plaintext.length=${plaintext.length} '
      'padding.bytes=${_countPaddingBytes(plaintext)}');
  final frames = _parseFrames(plaintext);
  return _PacketInspection(
    packetEnd - packetStart,
    _InspectedPacket(
      type: -1,
      level: _QuicEncryptionLevel.application,
      destinationConnectionId: match.destinationConnectionId,
      sourceConnectionId: Uint8List(0),
      packetNumber: packetNumber,
      cryptoFrames: frames.cryptoFrames,
      blockedFrames: frames.blockedFrames,
      streamFrames: frames.streamFrames,
      pathChallenges: frames.pathChallenges,
      datagrams: frames.datagrams,
      connectionClose: frames.connectionClose,
      initialToken: Uint8List(0),
    ),
  );
}

_FrameSummary _parseFrames(Uint8List plaintext) {
  final cryptoFrames = <_CryptoFrame>[];
  final blockedFrames = <_BlockedFrame>[];
  final streamFrames = <_StreamFrame>[];
  final datagrams = <Uint8List>[];
  final pathChallenges = <Uint8List>[];
  var offset = 0;
  var paddingRun = 0;
  while (offset < plaintext.length) {
    final frameStart = offset;
    final frameType = _readVarInt(plaintext, offset);
    if (frameType == null) {
      print('  frame@$frameStart ERROR truncated frame type');
      return _FrameSummary(cryptoFrames);
    }
    offset = frameType.nextOffset;
    if (frameType.value == 0) {
      paddingRun++;
      continue;
    }
    if (paddingRun != 0) {
      print('  frame PADDING length=$paddingRun');
      paddingRun = 0;
    }

    switch (frameType.value) {
      case 0x01:
        print('  frame@$frameStart PING');
      case 0x04:
        final streamId = _readVarInt(plaintext, offset);
        final errorCode = streamId == null
            ? null
            : _readVarInt(plaintext, streamId.nextOffset);
        final finalSize = errorCode == null
            ? null
            : _readVarInt(plaintext, errorCode.nextOffset);
        if (streamId == null || errorCode == null || finalSize == null) {
          return _FrameSummary(cryptoFrames);
        }
        offset = finalSize.nextOffset;
        print('  frame@$frameStart RESET_STREAM id=${streamId.value} '
            'error=${errorCode.value} finalSize=${finalSize.value}');
      case 0x05:
        final streamId = _readVarInt(plaintext, offset);
        final errorCode = streamId == null
            ? null
            : _readVarInt(plaintext, streamId.nextOffset);
        if (streamId == null || errorCode == null) {
          return _FrameSummary(cryptoFrames);
        }
        offset = errorCode.nextOffset;
        print('  frame@$frameStart STOP_SENDING id=${streamId.value} '
            'error=${errorCode.value}');
      case 0x12:
      case 0x13:
        final maximumStreams = _readVarInt(plaintext, offset);
        if (maximumStreams == null) {
          return _FrameSummary(cryptoFrames);
        }
        offset = maximumStreams.nextOffset;
        final direction = frameType.value == 0x12 ? 'BIDI' : 'UNI';
        print('  frame@$frameStart MAX_STREAMS_$direction '
            'maximum=${maximumStreams.value}');
      case 0x02:
      case 0x03:
        final largest = _readVarInt(plaintext, offset);
        final delay =
            largest == null ? null : _readVarInt(plaintext, largest.nextOffset);
        final count =
            delay == null ? null : _readVarInt(plaintext, delay.nextOffset);
        final firstRange =
            count == null ? null : _readVarInt(plaintext, count.nextOffset);
        if (largest == null ||
            delay == null ||
            count == null ||
            firstRange == null) {
          print('  frame@$frameStart ACK ERROR truncated');
          return _FrameSummary(cryptoFrames);
        }
        offset = firstRange.nextOffset;
        print('  frame@$frameStart ACK largest=${largest.value} '
            'delay=${delay.value} ranges=${count.value}');
        for (var i = 0; i < count.value; i++) {
          final gap = _readVarInt(plaintext, offset);
          final range =
              gap == null ? null : _readVarInt(plaintext, gap.nextOffset);
          if (gap == null || range == null) {
            print('  frame@$frameStart ACK ERROR truncated range');
            return _FrameSummary(cryptoFrames);
          }
          offset = range.nextOffset;
        }
      case 0x06:
        final cryptoOffset = _readVarInt(plaintext, offset);
        final length = cryptoOffset == null
            ? null
            : _readVarInt(plaintext, cryptoOffset.nextOffset);
        if (cryptoOffset == null || length == null) {
          print('  frame@$frameStart CRYPTO ERROR truncated header');
          return _FrameSummary(cryptoFrames);
        }
        offset = length.nextOffset;
        if (offset + length.value > plaintext.length) {
          print('  frame@$frameStart CRYPTO ERROR truncated body');
          return _FrameSummary(cryptoFrames);
        }
        final cryptoBytes = Uint8List.fromList(
          plaintext.sublist(offset, offset + length.value),
        );
        cryptoFrames.add(_CryptoFrame(cryptoOffset.value, cryptoBytes));
        print('  frame@$frameStart CRYPTO offset=${cryptoOffset.value} '
            'length=${length.value}');
        if (cryptoOffset.value == 0 && cryptoBytes.isNotEmpty) {
          _parseTlsHandshake(cryptoBytes);
        }
        offset += length.value;
      case >= 0x08 && <= 0x0f:
        final streamId = _readVarInt(plaintext, offset);
        if (streamId == null) {
          print('  frame@$frameStart STREAM ERROR truncated stream id');
          return _FrameSummary(cryptoFrames);
        }
        offset = streamId.nextOffset;
        var streamOffset = 0;
        if ((frameType.value & 0x04) != 0) {
          final parsed = _readVarInt(plaintext, offset);
          if (parsed == null) {
            print('  frame@$frameStart STREAM ERROR truncated offset');
            return _FrameSummary(cryptoFrames);
          }
          streamOffset = parsed.value;
          offset = parsed.nextOffset;
        }
        late int length;
        if ((frameType.value & 0x02) != 0) {
          final parsed = _readVarInt(plaintext, offset);
          if (parsed == null) {
            print('  frame@$frameStart STREAM ERROR truncated length');
            return _FrameSummary(cryptoFrames);
          }
          length = parsed.value;
          offset = parsed.nextOffset;
        } else {
          length = plaintext.length - offset;
        }
        if (offset + length > plaintext.length) {
          print('  frame@$frameStart STREAM ERROR truncated body');
          return _FrameSummary(cryptoFrames);
        }
        print('  frame@$frameStart STREAM id=${streamId.value} '
            'offset=$streamOffset length=$length fin=${(frameType.value & 1) != 0}');
        streamFrames.add(_StreamFrame(
          streamId: streamId.value,
          offset: streamOffset,
          data: Uint8List.fromList(plaintext.sublist(offset, offset + length)),
          fin: (frameType.value & 1) != 0,
        ));
        offset += length;
      case 0x1c:
      case 0x1d:
        final errorCode = _readVarInt(plaintext, offset);
        final triggeringFrame = frameType.value == 0x1c && errorCode != null
            ? _readVarInt(plaintext, errorCode.nextOffset)
            : null;
        final reasonOffset =
            triggeringFrame?.nextOffset ?? errorCode?.nextOffset;
        final reasonLength =
            reasonOffset == null ? null : _readVarInt(plaintext, reasonOffset);
        if (errorCode == null ||
            (frameType.value == 0x1c && triggeringFrame == null) ||
            reasonLength == null ||
            reasonLength.nextOffset + reasonLength.value > plaintext.length) {
          print('  frame@$frameStart CONNECTION_CLOSE ERROR malformed');
          return _FrameSummary(cryptoFrames);
        }
        final reason = utf8.decode(
          plaintext.sublist(
            reasonLength.nextOffset,
            reasonLength.nextOffset + reasonLength.value,
          ),
          allowMalformed: true,
        );
        print('  frame@$frameStart CONNECTION_CLOSE '
            '${frameType.value == 0x1c ? 'transport' : 'application'} '
            'error=${errorCode.value}'
            '${triggeringFrame == null ? '' : ' frame=${triggeringFrame.value}'} '
            'reason="$reason"');
        return _FrameSummary(
          cryptoFrames,
          blockedFrames,
          streamFrames,
          true,
        );
      case 0x07:
        final tokenLength = _readVarInt(plaintext, offset);
        if (tokenLength == null ||
            tokenLength.nextOffset + tokenLength.value > plaintext.length) {
          return _FrameSummary(cryptoFrames);
        }
        offset = tokenLength.nextOffset + tokenLength.value;
        print('  frame@$frameStart NEW_TOKEN length=${tokenLength.value}');
      case 0x18:
        final sequence = _readVarInt(plaintext, offset);
        final retirePriorTo = sequence == null
            ? null
            : _readVarInt(plaintext, sequence.nextOffset);
        if (sequence == null ||
            retirePriorTo == null ||
            retirePriorTo.nextOffset >= plaintext.length) {
          return _FrameSummary(cryptoFrames);
        }
        offset = retirePriorTo.nextOffset;
        final connectionIdLength = plaintext[offset++];
        if (offset + connectionIdLength + 16 > plaintext.length) {
          return _FrameSummary(cryptoFrames);
        }
        final connectionId = Uint8List.fromList(
          plaintext.sublist(offset, offset + connectionIdLength),
        );
        offset += connectionIdLength + 16;
        print('  frame@$frameStart NEW_CONNECTION_ID '
            'sequence=${sequence.value} retirePriorTo=${retirePriorTo.value} '
            'cid=${_hex(connectionId)}');
      case 0x19:
        final sequence = _readVarInt(plaintext, offset);
        if (sequence == null) return _FrameSummary(cryptoFrames);
        offset = sequence.nextOffset;
        print('  frame@$frameStart RETIRE_CONNECTION_ID '
            'sequence=${sequence.value}');
      case 0x1a:
      case 0x1b:
        if (offset + 8 > plaintext.length) {
          return _FrameSummary(cryptoFrames);
        }
        final pathData =
            Uint8List.fromList(plaintext.sublist(offset, offset + 8));
        offset += 8;
        if (frameType.value == 0x1a) {
          pathChallenges.add(pathData);
        }
        print('  frame@$frameStart '
            '${frameType.value == 0x1a ? 'PATH_CHALLENGE' : 'PATH_RESPONSE'} '
            'data=${_hex(pathData)}');
      case 0x14:
        final maximumData = _readVarInt(plaintext, offset);
        if (maximumData == null) {
          return _FrameSummary(cryptoFrames);
        }
        offset = maximumData.nextOffset;
        blockedFrames.add(_BlockedFrame.data());
        print('  frame@$frameStart DATA_BLOCKED limit=${maximumData.value}');
      case 0x15:
        final streamId = _readVarInt(plaintext, offset);
        final maximumStreamData = streamId == null
            ? null
            : _readVarInt(plaintext, streamId.nextOffset);
        if (streamId == null || maximumStreamData == null) {
          return _FrameSummary(cryptoFrames);
        }
        offset = maximumStreamData.nextOffset;
        blockedFrames.add(_BlockedFrame.stream(streamId.value));
        print('  frame@$frameStart STREAM_DATA_BLOCKED id=${streamId.value} '
            'limit=${maximumStreamData.value}');
      case 0x30:
      case 0x31:
        late int length;
        if (frameType.value == 0x31) {
          final parsed = _readVarInt(plaintext, offset);
          if (parsed == null) {
            print('  frame@$frameStart DATAGRAM ERROR truncated length');
            return _FrameSummary(cryptoFrames);
          }
          length = parsed.value;
          offset = parsed.nextOffset;
        } else {
          length = plaintext.length - offset;
        }
        if (offset + length > plaintext.length) {
          print('  frame@$frameStart DATAGRAM ERROR truncated body');
          return _FrameSummary(cryptoFrames);
        }
        final payload =
            Uint8List.fromList(plaintext.sublist(offset, offset + length));
        datagrams.add(payload);
        print('  frame@$frameStart DATAGRAM length=$length '
            'prefix=${_formatBytes(payload.take(16).toList())}');
        if (payload.isNotEmpty) {
          print('    DATAGRAM payload decode:');
          _parseFrames(payload);
        }
        offset += length;
        if (frameType.value == 0x30) {
          return _FrameSummary(cryptoFrames);
        }
      default:
        print('  frame@$frameStart type=0x${frameType.value.toRadixString(16)} '
            'not decoded; stopping');
        return _FrameSummary(cryptoFrames);
    }
  }
  if (paddingRun != 0) {
    print('  frame PADDING length=$paddingRun');
  }
  return _FrameSummary(
    cryptoFrames,
    blockedFrames,
    streamFrames,
    false,
    pathChallenges,
    datagrams,
  );
}

void _parseTlsHandshake(Uint8List bytes) {
  if (bytes.length < 4) {
    print('    TLS handshake truncated');
    return;
  }
  final type = bytes[0];
  final length = (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  print('    TLS handshake type=$type length=$length');
  if (type != 1 || bytes.length < 4 + length) {
    return;
  }
  var offset = 4;
  if (offset + 34 > bytes.length) return;
  final legacyVersion = (bytes[offset] << 8) | bytes[offset + 1];
  offset += 2 + 32;
  if (offset >= bytes.length) return;
  final sessionIdLength = bytes[offset++];
  offset += sessionIdLength;
  if (offset + 2 > bytes.length) return;
  final cipherSuitesLength = (bytes[offset] << 8) | bytes[offset + 1];
  offset += 2 + cipherSuitesLength;
  if (offset >= bytes.length) return;
  final compressionLength = bytes[offset++];
  offset += compressionLength;
  if (offset + 2 > bytes.length) return;
  final extensionsLength = (bytes[offset] << 8) | bytes[offset + 1];
  offset += 2;
  print('    ClientHello legacyVersion=0x${legacyVersion.toRadixString(16)} '
      'sessionId=$sessionIdLength cipherSuites=$cipherSuitesLength '
      'compression=$compressionLength extensions=$extensionsLength');
  final extensionsEnd = offset + extensionsLength;
  while (offset + 4 <= extensionsEnd && offset + 4 <= bytes.length) {
    final extensionType = (bytes[offset] << 8) | bytes[offset + 1];
    final extensionLength = (bytes[offset + 2] << 8) | bytes[offset + 3];
    offset += 4;
    print('      ext ${_tlsExtensionName(extensionType)} '
        '(0x${extensionType.toRadixString(16).padLeft(4, '0')}) '
        'length=$extensionLength');
    offset += extensionLength;
  }
}

int _countPaddingBytes(Uint8List plaintext) {
  var count = 0;
  for (var i = plaintext.length - 1; i >= 0; i--) {
    if (plaintext[i] != 0) break;
    count++;
  }
  return count;
}

String _longPacketTypeName(int type) {
  return switch (type) {
    0 => 'Initial',
    1 => '0-RTT',
    2 => 'Handshake',
    3 => 'Retry',
    _ => 'unknown',
  };
}

String _tlsExtensionName(int type) {
  return switch (type) {
    0x0000 => 'server_name',
    0x0005 => 'status_request',
    0x000a => 'supported_groups',
    0x000b => 'ec_point_formats',
    0x000d => 'signature_algorithms',
    0x0010 => 'alpn',
    0x0012 => 'signed_certificate_timestamp',
    0x001b => 'compress_certificate',
    0x0023 => 'session_ticket',
    0x0029 => 'pre_shared_key',
    0x002b => 'supported_versions',
    0x002d => 'psk_key_exchange_modes',
    0x0033 => 'key_share',
    0x0039 => 'quic_transport_parameters',
    0xffa5 => 'quic_transport_parameters_legacy',
    _ when (type & 0x0f0f) == 0x0a0a => 'GREASE',
    _ => 'unknown',
  };
}

int _readUint32(Uint8List bytes, int offset) {
  return (bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3];
}

int _readPacketNumber(Uint8List bytes, int offset, int length) {
  var value = 0;
  for (var i = 0; i < length; i++) {
    value = (value << 8) | bytes[offset + i];
  }
  return value;
}

_VarInt? _readVarInt(Uint8List bytes, int offset) {
  if (offset >= bytes.length) return null;
  final first = bytes[offset];
  final length = 1 << (first >> 6);
  if (offset + length > bytes.length) return null;
  var value = first & 0x3f;
  for (var i = 1; i < length; i++) {
    value = (value << 8) | bytes[offset + i];
  }
  return _VarInt(value, offset + length);
}

void _appendVarInt(BytesBuilder out, int value) {
  if (value < 0x40) {
    out.addByte(value);
  } else if (value < 0x4000) {
    out
      ..addByte(0x40 | ((value >> 8) & 0x3f))
      ..addByte(value & 0xff);
  } else if (value < 0x40000000) {
    out
      ..addByte(0x80 | ((value >> 24) & 0x3f))
      ..addByte((value >> 16) & 0xff)
      ..addByte((value >> 8) & 0xff)
      ..addByte(value & 0xff);
  } else {
    out
      ..addByte(0xc0 | ((value >> 56) & 0x3f))
      ..addByte((value >> 48) & 0xff)
      ..addByte((value >> 40) & 0xff)
      ..addByte((value >> 32) & 0xff)
      ..addByte((value >> 24) & 0xff)
      ..addByte((value >> 16) & 0xff)
      ..addByte((value >> 8) & 0xff)
      ..addByte(value & 0xff);
  }
}

void _appendAckFrame(BytesBuilder out, int largestAcknowledged) {
  _appendVarInt(out, 0x02);
  _appendVarInt(out, largestAcknowledged);
  _appendVarInt(out, 0);
  _appendVarInt(out, 0);
  _appendVarInt(out, 0);
}

void _appendAckRangesFrame(BytesBuilder out, SplayTreeSet<int> packetNumbers) {
  if (packetNumbers.isEmpty) return;
  final ranges = <(int, int)>[];
  int? rangeStart;
  int? rangeEnd;
  for (final packetNumber in packetNumbers.toList().reversed) {
    if (rangeEnd == null) {
      rangeStart = packetNumber;
      rangeEnd = packetNumber;
    } else if (packetNumber == rangeStart! - 1) {
      rangeStart = packetNumber;
    } else {
      ranges.add((rangeStart, rangeEnd));
      rangeStart = packetNumber;
      rangeEnd = packetNumber;
    }
  }
  ranges.add((rangeStart!, rangeEnd!));
  if (ranges.length > 32) {
    ranges.removeRange(32, ranges.length);
  }

  _appendVarInt(out, 0x02);
  _appendVarInt(out, ranges.first.$2);
  _appendVarInt(out, 0);
  _appendVarInt(out, ranges.length - 1);
  _appendVarInt(out, ranges.first.$2 - ranges.first.$1);
  for (var i = 1; i < ranges.length; i++) {
    final higher = ranges[i - 1];
    final lower = ranges[i];
    _appendVarInt(out, higher.$1 - lower.$2 - 2);
    _appendVarInt(out, lower.$2 - lower.$1);
  }
}

void _appendCryptoFrame(BytesBuilder out, int offset, Uint8List data) {
  _appendVarInt(out, 0x06);
  _appendVarInt(out, offset);
  _appendVarInt(out, data.length);
  out.add(data);
}

void _appendMaxDataFrame(BytesBuilder out, int maximumData) {
  _appendVarInt(out, 0x10);
  _appendVarInt(out, maximumData);
}

void _appendMaxStreamDataFrame(
  BytesBuilder out,
  int streamId,
  int maximumStreamData,
) {
  _appendVarInt(out, 0x11);
  _appendVarInt(out, streamId);
  _appendVarInt(out, maximumStreamData);
}

void _appendResetStreamFrame(
  BytesBuilder out,
  int streamId,
  int errorCode,
  int finalSize,
) {
  _appendVarInt(out, 0x04);
  _appendVarInt(out, streamId);
  _appendVarInt(out, errorCode);
  _appendVarInt(out, finalSize);
}

void _appendStopSendingFrame(
  BytesBuilder out,
  int streamId,
  int errorCode,
) {
  _appendVarInt(out, 0x05);
  _appendVarInt(out, streamId);
  _appendVarInt(out, errorCode);
}

void _appendNewConnectionIdFrame(
  BytesBuilder out, {
  required int sequence,
  required int retirePriorTo,
  required Uint8List connectionId,
  required Uint8List statelessResetToken,
}) {
  _appendVarInt(out, 0x18);
  _appendVarInt(out, sequence);
  _appendVarInt(out, retirePriorTo);
  out.addByte(connectionId.length);
  out.add(connectionId);
  out.add(statelessResetToken);
}

void _appendPathChallengeFrame(BytesBuilder out, Uint8List data) {
  _appendVarInt(out, 0x1a);
  out.add(data);
}

void _appendPathResponseFrame(BytesBuilder out, Uint8List data) {
  _appendVarInt(out, 0x1b);
  out.add(data);
}

void _appendNewTokenFrame(BytesBuilder out, Uint8List token) {
  _appendVarInt(out, 0x07);
  _appendVarInt(out, token.length);
  out.add(token);
}

Uint8List _buildVersionNegotiationPacket(
  _InspectedPacket packet, {
  required bool includeVersion1,
}) {
  final out = BytesBuilder(copy: false)
    ..addByte(0xc0)
    ..add(const [0, 0, 0, 0])
    ..addByte(packet.sourceConnectionId.length)
    ..add(packet.sourceConnectionId)
    ..addByte(packet.destinationConnectionId.length)
    ..add(packet.destinationConnectionId);
  if (includeVersion1) {
    out.add(_uint32Bytes(_quicVersion1));
  }
  out.add(_uint32Bytes(0xfaceb00c));
  return out.takeBytes();
}

Uint8List _buildRetryPacket(
  _BoringSslCrypto crypto,
  _InspectedPacket packet,
  Uint8List serverConnectionId,
  Uint8List token,
) {
  final header = BytesBuilder(copy: false)
    ..addByte(0xf0)
    ..add(_uint32Bytes(_quicVersion1))
    ..addByte(packet.sourceConnectionId.length)
    ..add(packet.sourceConnectionId)
    ..addByte(serverConnectionId.length)
    ..add(serverConnectionId)
    ..add(token);
  final retryWithoutTag = header.takeBytes();
  final pseudoPacket = BytesBuilder(copy: false)
    ..addByte(packet.destinationConnectionId.length)
    ..add(packet.destinationConnectionId)
    ..add(retryWithoutTag);
  final tag = crypto.seal(
    key: Uint8List.fromList(const [
      0xbe,
      0x0c,
      0x69,
      0x0b,
      0x9f,
      0x66,
      0x57,
      0x5a,
      0x1d,
      0x76,
      0x6b,
      0x54,
      0xe3,
      0x68,
      0xc8,
      0x4e,
    ]),
    nonce: Uint8List.fromList(const [
      0x46,
      0x15,
      0x99,
      0xd3,
      0x5d,
      0x63,
      0x2b,
      0xf2,
      0x23,
      0x98,
      0x25,
      0xbb,
    ]),
    plaintext: Uint8List(0),
    aad: pseudoPacket.takeBytes(),
    cipherId: _tlsAes128GcmSha256,
  );
  return Uint8List.fromList([...retryWithoutTag, ...tag]);
}

void _appendStreamFrame(
  BytesBuilder out, {
  required int streamId,
  required int offset,
  required Uint8List data,
  required bool fin,
}) {
  var frameType = 0x08 | 0x02;
  if (offset != 0) frameType |= 0x04;
  if (fin) frameType |= 0x01;
  _appendVarInt(out, frameType);
  _appendVarInt(out, streamId);
  if (offset != 0) {
    _appendVarInt(out, offset);
  }
  _appendVarInt(out, data.length);
  out.add(data);
}

void _appendDatagramFrame(BytesBuilder out, Uint8List data) {
  _appendVarInt(out, 0x31);
  _appendVarInt(out, data.length);
  out.add(data);
}

Uint8List _serverTransportParameters({
  required Uint8List originalDestinationConnectionId,
  required Uint8List initialSourceConnectionId,
  Uint8List? retrySourceConnectionId,
  int? preferredIpv4Port,
  required int initialMaxData,
  required int initialMaxStreamData,
  required int maxIdleTimeout,
}) {
  final out = BytesBuilder(copy: false);
  _appendTransportParameterBytes(out, 0x00, originalDestinationConnectionId);
  _appendTransportParameterInt(out, 0x01, maxIdleTimeout);
  _appendTransportParameterInt(out, 0x03, _quicMaxDatagramPayloadSize);
  _appendTransportParameterInt(out, 0x04, initialMaxData);
  _appendTransportParameterInt(out, 0x05, initialMaxStreamData);
  _appendTransportParameterInt(out, 0x06, initialMaxStreamData);
  _appendTransportParameterInt(out, 0x07, initialMaxStreamData);
  _appendTransportParameterInt(out, 0x08, 16);
  _appendTransportParameterInt(out, 0x09, 16);
  if (preferredIpv4Port != null) {
    final preferred = BytesBuilder(copy: false)
      ..add(const [127, 0, 0, 1])
      ..add([
        (preferredIpv4Port >> 8) & 0xff,
        preferredIpv4Port & 0xff,
      ])
      ..add(Uint8List(16))
      ..add(const [0, 0])
      ..addByte(_preferredServerConnectionId.length)
      ..add(_preferredServerConnectionId)
      ..add(_preferredStatelessResetToken);
    _appendTransportParameterBytes(out, 0x0d, preferred.takeBytes());
  }
  _appendTransportParameterInt(out, 0x0e, 2);
  _appendTransportParameterBytes(out, 0x0f, initialSourceConnectionId);
  _appendTransportParameterInt(out, 0x20, _quicMaxDatagramPayloadSize);
  if (retrySourceConnectionId != null) {
    _appendTransportParameterBytes(out, 0x10, retrySourceConnectionId);
  }
  return out.takeBytes();
}

void _appendTransportParameterInt(BytesBuilder out, int id, int value) {
  final encoded = BytesBuilder(copy: false);
  _appendVarInt(encoded, value);
  _appendTransportParameterBytes(out, id, encoded.takeBytes());
}

void _appendTransportParameterBytes(BytesBuilder out, int id, Uint8List value) {
  _appendVarInt(out, id);
  _appendVarInt(out, value.length);
  out.add(value);
}

Uint8List _uint32Bytes(int value) {
  return Uint8List.fromList([
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ]);
}

int _toBoringSslLevel(_QuicEncryptionLevel level) {
  return switch (level) {
    _QuicEncryptionLevel.initial => 0,
    _QuicEncryptionLevel.earlyData => 1,
    _QuicEncryptionLevel.handshake => 2,
    _QuicEncryptionLevel.application => 3,
  };
}

_QuicEncryptionLevel _fromBoringSslLevel(int level) {
  return switch (level) {
    0 => _QuicEncryptionLevel.initial,
    1 => _QuicEncryptionLevel.earlyData,
    2 => _QuicEncryptionLevel.handshake,
    3 => _QuicEncryptionLevel.application,
    _ => throw ArgumentError.value(level, 'level', 'unknown QUIC level'),
  };
}

String _hex(List<int> bytes) {
  return bytes.map(_hexByte).join();
}

String _hexByte(int byte) {
  return byte.toRadixString(16).padLeft(2, '0');
}

String _formatBytes(List<int> bytes) {
  return '[${bytes.join(', ')}]';
}

class _VarInt {
  _VarInt(this.value, this.nextOffset);

  final int value;
  final int nextOffset;
}

enum _QuicEncryptionLevel {
  initial,
  earlyData,
  handshake,
  application,
}

class _PacketProtection {
  _PacketProtection({
    required this.level,
    required this.keys,
    required this.cipherId,
  });

  final _QuicEncryptionLevel level;
  final _QuicPacketKeys keys;
  final int cipherId;
}

class _ShortHeaderProtectionMatch {
  _ShortHeaderProtectionMatch({
    required this.destinationConnectionId,
    required this.protection,
  });

  final Uint8List destinationConnectionId;
  final _PacketProtection protection;
}

class _PacketInspection {
  _PacketInspection(this.consumed, this.packet);

  final int consumed;
  final _InspectedPacket? packet;
}

class _InspectedPacket {
  _InspectedPacket({
    required this.type,
    required this.level,
    required this.destinationConnectionId,
    required this.sourceConnectionId,
    required this.packetNumber,
    required this.cryptoFrames,
    required this.blockedFrames,
    required this.streamFrames,
    required this.pathChallenges,
    required this.datagrams,
    required this.connectionClose,
    required this.initialToken,
  });

  final int type;
  final _QuicEncryptionLevel level;
  final Uint8List destinationConnectionId;
  final Uint8List sourceConnectionId;
  final int packetNumber;
  final List<_CryptoFrame> cryptoFrames;
  final List<_BlockedFrame> blockedFrames;
  final List<_StreamFrame> streamFrames;
  final List<Uint8List> pathChallenges;
  final List<Uint8List> datagrams;
  final bool connectionClose;
  final Uint8List initialToken;
}

class _CryptoFrame {
  _CryptoFrame(this.offset, this.data);

  final int offset;
  final Uint8List data;
}

class _CryptoStreamReassembler {
  final _pending = SplayTreeMap<int, Uint8List>();
  int _nextOffset = 0;

  List<Uint8List> add(int offset, Uint8List data) {
    if (data.isEmpty || offset + data.length <= _nextOffset) {
      return const [];
    }
    if (offset < _nextOffset) {
      data = Uint8List.sublistView(data, _nextOffset - offset);
      offset = _nextOffset;
    }

    var mergedStart = offset;
    var mergedEnd = offset + data.length;
    final overlapping = _pending.entries
        .where(
          (entry) =>
              entry.key <= mergedEnd &&
              entry.key + entry.value.length >= mergedStart,
        )
        .toList();
    for (final entry in overlapping) {
      mergedStart = entry.key < mergedStart ? entry.key : mergedStart;
      final end = entry.key + entry.value.length;
      mergedEnd = end > mergedEnd ? end : mergedEnd;
    }

    final merged = Uint8List(mergedEnd - mergedStart);
    for (final entry in overlapping) {
      merged.setRange(
        entry.key - mergedStart,
        entry.key - mergedStart + entry.value.length,
        entry.value,
      );
      _pending.remove(entry.key);
    }
    merged.setRange(
        offset - mergedStart, offset - mergedStart + data.length, data);
    _pending[mergedStart] = merged;

    final ready = <Uint8List>[];
    var bytes = _pending[_nextOffset];
    while (bytes != null) {
      _pending.remove(_nextOffset);
      ready.add(bytes);
      _nextOffset += bytes.length;
      bytes = _pending[_nextOffset];
    }
    return ready;
  }
}

class _FrameSummary {
  _FrameSummary(
    this.cryptoFrames, [
    this.blockedFrames = const [],
    this.streamFrames = const [],
    this.connectionClose = false,
    this.pathChallenges = const [],
    this.datagrams = const [],
  ]);

  final List<_CryptoFrame> cryptoFrames;
  final List<_BlockedFrame> blockedFrames;
  final List<_StreamFrame> streamFrames;
  final bool connectionClose;
  final List<Uint8List> pathChallenges;
  final List<Uint8List> datagrams;
}

class _StreamFrame {
  const _StreamFrame({
    required this.streamId,
    required this.offset,
    required this.data,
    required this.fin,
  });

  final int streamId;
  final int offset;
  final Uint8List data;
  final bool fin;

  int get length => data.length;
}

class _BlockedFrame {
  const _BlockedFrame.data() : streamId = null;
  const _BlockedFrame.stream(this.streamId);

  final int? streamId;
}

class _QuicPacketKeys {
  _QuicPacketKeys({
    required this.key,
    required this.iv,
    required this.hp,
  });

  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;

  Uint8List nonce(int packetNumber) {
    final nonce = Uint8List.fromList(iv);
    var pn = packetNumber;
    for (var i = 0; i < 8; i++) {
      nonce[nonce.length - 1 - i] ^= pn & 0xff;
      pn >>= 8;
    }
    return nonce;
  }
}

class _InspectorOptions {
  _InspectorOptions({
    required this.port,
    required this.sslLibraryPath,
    required this.cryptoLibraryPath,
    required this.certificateFile,
    required this.privateKeyFile,
    required this.dropFirstClientDatagram,
    required this.initialMaxData,
    required this.initialMaxStreamData,
    required this.maxIdleTimeout,
    required this.terminateFirstClientStream,
    required this.completeResponseResetNoError,
    required this.keyUpdateAfterHandshake,
    required this.closeAfterHandshake,
    required this.probeClientClose,
    required this.versionNegotiation,
    required this.versionNegotiationIncludesV1,
    required this.statelessResetAfterHandshake,
    required this.rotateConnectionId,
    required this.pathChallengeAfterHandshake,
    required this.newToken,
    required this.retry,
    required this.preferredAddress,
    required this.rejectResumedEarlyData,
    required this.dynamicQpackResponse,
    required this.redirectLocation,
    required this.responseAltSvc,
    required this.goawayAfterFirstRequest,
    required this.rejectFirstRequestWithGoaway,
    required this.echoApplicationData,
    required this.sendFlowControlViolation,
    required this.listenIpv6,
    required this.quiet,
  });

  final int port;
  final String sslLibraryPath;
  final String cryptoLibraryPath;
  final String? certificateFile;
  final String? privateKeyFile;
  final bool dropFirstClientDatagram;
  final int initialMaxData;
  final int initialMaxStreamData;
  final int maxIdleTimeout;
  final bool terminateFirstClientStream;
  final bool completeResponseResetNoError;
  final bool keyUpdateAfterHandshake;
  final bool closeAfterHandshake;
  final bool probeClientClose;
  final bool versionNegotiation;
  final bool versionNegotiationIncludesV1;
  final bool statelessResetAfterHandshake;
  final bool rotateConnectionId;
  final bool pathChallengeAfterHandshake;
  final bool newToken;
  final bool retry;
  final bool preferredAddress;
  final bool rejectResumedEarlyData;
  final bool dynamicQpackResponse;
  final String? redirectLocation;
  final String? responseAltSvc;
  final bool goawayAfterFirstRequest;
  final bool rejectFirstRequestWithGoaway;
  final bool echoApplicationData;
  final bool sendFlowControlViolation;
  final bool listenIpv6;
  final bool quiet;

  static _InspectorOptions parse(List<String> args) {
    var port = _defaultPort;
    var sslLibraryPath = _defaultSslLibrary;
    var cryptoLibraryPath = _defaultCryptoLibrary;
    String? certificateFile;
    String? privateKeyFile;
    var dropFirstClientDatagram = false;
    var initialMaxData = 1048576;
    var initialMaxStreamData = 262144;
    var maxIdleTimeout = 30000;
    var terminateFirstClientStream = false;
    var completeResponseResetNoError = false;
    var keyUpdateAfterHandshake = false;
    var closeAfterHandshake = false;
    var probeClientClose = false;
    var versionNegotiation = false;
    var versionNegotiationIncludesV1 = false;
    var statelessResetAfterHandshake = false;
    var rotateConnectionId = false;
    var pathChallengeAfterHandshake = false;
    var newToken = false;
    var retry = false;
    var preferredAddress = false;
    var rejectResumedEarlyData = false;
    var dynamicQpackResponse = false;
    String? redirectLocation;
    String? responseAltSvc;
    var goawayAfterFirstRequest = false;
    var rejectFirstRequestWithGoaway = false;
    var echoApplicationData = false;
    var sendFlowControlViolation = false;
    var listenIpv6 = false;
    var quiet = false;
    for (var i = 0; i < args.length; i++) {
      switch (args[i]) {
        case '--port':
          port = int.parse(args[++i]);
        case '--ssl':
          sslLibraryPath = args[++i];
        case '--crypto':
          cryptoLibraryPath = args[++i];
        case '--cert':
          certificateFile = args[++i];
        case '--key':
          privateKeyFile = args[++i];
        case '--drop-first-client-datagram':
          dropFirstClientDatagram = true;
        case '--initial-max-data':
          initialMaxData = int.parse(args[++i]);
        case '--initial-max-stream-data':
          initialMaxStreamData = int.parse(args[++i]);
        case '--max-idle-timeout':
          maxIdleTimeout = int.parse(args[++i]);
        case '--terminate-first-client-stream':
          terminateFirstClientStream = true;
        case '--complete-response-reset-no-error':
          completeResponseResetNoError = true;
        case '--key-update-after-handshake':
          keyUpdateAfterHandshake = true;
        case '--close-after-handshake':
          closeAfterHandshake = true;
        case '--probe-client-close':
          probeClientClose = true;
        case '--version-negotiation':
          versionNegotiation = true;
        case '--version-negotiation-includes-v1':
          versionNegotiation = true;
          versionNegotiationIncludesV1 = true;
        case '--stateless-reset-after-handshake':
          statelessResetAfterHandshake = true;
        case '--rotate-connection-id':
          rotateConnectionId = true;
        case '--path-challenge-after-handshake':
          pathChallengeAfterHandshake = true;
        case '--new-token':
          newToken = true;
        case '--retry':
          retry = true;
        case '--preferred-address':
          preferredAddress = true;
        case '--reject-resumed-early-data':
          rejectResumedEarlyData = true;
        case '--dynamic-qpack-response':
          dynamicQpackResponse = true;
        case '--redirect-location':
          redirectLocation = args[++i];
        case '--response-alt-svc':
          responseAltSvc = args[++i];
        case '--goaway-after-first-request':
          goawayAfterFirstRequest = true;
        case '--reject-first-request-with-goaway':
          rejectFirstRequestWithGoaway = true;
        case '--echo-application-data':
          echoApplicationData = true;
        case '--send-flow-control-violation':
          sendFlowControlViolation = true;
        case '--listen-ipv6':
          listenIpv6 = true;
        case '--quiet':
          quiet = true;
        case '--help':
        case '-h':
          _printUsageAndExit();
        default:
          if (!args[i].startsWith('-')) {
            port = int.parse(args[i]);
          } else {
            throw ArgumentError('Unknown option ${args[i]}');
          }
      }
    }
    return _InspectorOptions(
      port: port,
      sslLibraryPath: sslLibraryPath,
      cryptoLibraryPath: cryptoLibraryPath,
      certificateFile: certificateFile,
      privateKeyFile: privateKeyFile,
      dropFirstClientDatagram: dropFirstClientDatagram,
      initialMaxData: initialMaxData,
      initialMaxStreamData: initialMaxStreamData,
      maxIdleTimeout: maxIdleTimeout,
      terminateFirstClientStream: terminateFirstClientStream,
      completeResponseResetNoError: completeResponseResetNoError,
      keyUpdateAfterHandshake: keyUpdateAfterHandshake,
      closeAfterHandshake: closeAfterHandshake,
      probeClientClose: probeClientClose,
      versionNegotiation: versionNegotiation,
      versionNegotiationIncludesV1: versionNegotiationIncludesV1,
      statelessResetAfterHandshake: statelessResetAfterHandshake,
      rotateConnectionId: rotateConnectionId,
      pathChallengeAfterHandshake: pathChallengeAfterHandshake,
      newToken: newToken,
      retry: retry,
      preferredAddress: preferredAddress,
      rejectResumedEarlyData: rejectResumedEarlyData,
      dynamicQpackResponse: dynamicQpackResponse,
      redirectLocation: redirectLocation,
      responseAltSvc: responseAltSvc,
      goawayAfterFirstRequest: goawayAfterFirstRequest,
      rejectFirstRequestWithGoaway: rejectFirstRequestWithGoaway,
      echoApplicationData: echoApplicationData,
      sendFlowControlViolation: sendFlowControlViolation,
      listenIpv6: listenIpv6,
      quiet: quiet,
    );
  }

  static Never _printUsageAndExit() {
    print('Usage: dart run bin/quic_inspector.dart [--port 4433] '
        '[--ssl path] [--crypto path] [--cert cert.pem --key key.pem] '
        '[--drop-first-client-datagram] [--initial-max-data bytes] '
        '[--initial-max-stream-data bytes] '
        '[--max-idle-timeout milliseconds] [--terminate-first-client-stream] '
        '[--complete-response-reset-no-error] '
        '[--key-update-after-handshake] [--close-after-handshake] '
        '[--probe-client-close] [--version-negotiation] '
        '[--version-negotiation-includes-v1] '
        '[--stateless-reset-after-handshake] [--rotate-connection-id] '
        '[--path-challenge-after-handshake] [--new-token] [--retry] '
        '[--send-flow-control-violation] [--listen-ipv6] '
        '[--quiet] '
        '[--preferred-address] [--reject-resumed-early-data] '
        '[--dynamic-qpack-response] [--redirect-location uri] '
        '[--response-alt-svc value] '
        '[--goaway-after-first-request] '
        '[--reject-first-request-with-goaway] [--echo-application-data]');
    exit(0);
  }
}

typedef _MallocNative = ffi.Pointer<ffi.Void> Function(
  ffi.IntPtr,
  ffi.Pointer<ffi.Int8>,
  ffi.Int32,
);
typedef _MallocDart = ffi.Pointer<ffi.Void> Function(
  int,
  ffi.Pointer<ffi.Int8>,
  int,
);
typedef _FreeNative = ffi.Void Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Int8>,
  ffi.Int32,
);
typedef _FreeDart = void Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Int8>,
  int,
);
typedef _NoArgConstPointerNative = ffi.Pointer<ffi.Void> Function();
typedef _NoArgConstPointerDart = ffi.Pointer<ffi.Void> Function();
typedef _HkdfExtractNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.IntPtr>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _HkdfExtractDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.IntPtr>,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _HkdfExpandNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _HkdfExpandDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _AeadCtxNewNative = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
  ffi.IntPtr,
);
typedef _AeadCtxNewDart = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  int,
  int,
);
typedef _AeadCtxFreeNative = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _AeadCtxFreeDart = void Function(ffi.Pointer<ffi.Void>);
typedef _AeadOpenNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.IntPtr>,
  ffi.IntPtr,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _AeadOpenDart = int Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.IntPtr>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _AeadSealNative = _AeadOpenNative;
typedef _AeadSealDart = _AeadOpenDart;
typedef _AesSetEncryptKeyNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Void>,
);
typedef _AesSetEncryptKeyDart = int Function(
  ffi.Pointer<ffi.Uint8>,
  int,
  ffi.Pointer<ffi.Void>,
);
typedef _AesEncryptNative = ffi.Void Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Void>,
);
typedef _AesEncryptDart = void Function(
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Void>,
);
typedef _SslCipherGetIdNative = ffi.Uint32 Function(ffi.Pointer<ffi.Void>);
typedef _SslCipherGetIdDart = int Function(ffi.Pointer<ffi.Void>);
typedef _TlsMethodNative = ffi.Pointer<ffi.Void> Function();
typedef _TlsMethodDart = ffi.Pointer<ffi.Void> Function();
typedef _SslCtxNewNative = ffi.Pointer<ffi.Void> Function(
  ffi.Pointer<ffi.Void>,
);
typedef _SslCtxNewDart = ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>);
typedef _SslCtxFreeNative = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _SslCtxFreeDart = void Function(ffi.Pointer<ffi.Void>);
typedef _SslNewNative = ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>);
typedef _SslNewDart = ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>);
typedef _SslFreeNative = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _SslFreeDart = void Function(ffi.Pointer<ffi.Void>);
typedef _SslVoidNative = ffi.Void Function(ffi.Pointer<ffi.Void>);
typedef _SslVoidDart = void Function(ffi.Pointer<ffi.Void>);
typedef _SslIntNative = ffi.Int32 Function(ffi.Pointer<ffi.Void>);
typedef _SslIntDart = int Function(ffi.Pointer<ffi.Void>);
typedef _SslUint16ArgNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Uint16,
);
typedef _SslUint16ArgDart = int Function(ffi.Pointer<ffi.Void>, int);
typedef _SslVoidIntArgNative = ffi.Void Function(
  ffi.Pointer<ffi.Void>,
  ffi.Int32,
);
typedef _SslVoidIntArgDart = void Function(ffi.Pointer<ffi.Void>, int);
typedef _SslGetErrorNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Int32,
);
typedef _SslGetErrorDart = int Function(ffi.Pointer<ffi.Void>, int);
typedef _SslSetQuicMethodNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<_SslQuicMethod>,
);
typedef _SslSetQuicMethodDart = int Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<_SslQuicMethod>,
);
typedef _SslSetQuicTransportParamsNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _SslSetQuicTransportParamsDart = int Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _SslSetBytesNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _SslSetBytesDart = int Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _SslProvideQuicDataNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Int32,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _SslProvideQuicDataDart = int Function(
  ffi.Pointer<ffi.Void>,
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _SslUseFileNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Int32,
);
typedef _SslUseFileDart = int Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _SslUseCertChainFileNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _SslUseCertChainFileDart = int Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
);
typedef _ErrGetErrorNative = ffi.Uint64 Function();
typedef _ErrGetErrorDart = int Function();
typedef _ErrStringNative = ffi.Void Function(
  ffi.Uint64,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _ErrStringDart = void Function(
  int,
  ffi.Pointer<ffi.Uint8>,
  int,
);
typedef _SetSecretNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Int32,
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _AddHandshakeDataNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Int32,
  ffi.Pointer<ffi.Uint8>,
  ffi.IntPtr,
);
typedef _FlushFlightNative = ffi.Int32 Function(ffi.Pointer<ffi.Void>);
typedef _SendAlertNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Int32,
  ffi.Uint8,
);
typedef _AlpnSelectNative = ffi.Int32 Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Pointer<ffi.Uint8>,
  ffi.Uint32,
  ffi.Pointer<ffi.Void>,
);
typedef _SslCtxSetAlpnSelectCbNative = ffi.Void Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.NativeFunction<_AlpnSelectNative>>,
  ffi.Pointer<ffi.Void>,
);
typedef _SslCtxSetAlpnSelectCbDart = void Function(
  ffi.Pointer<ffi.Void>,
  ffi.Pointer<ffi.NativeFunction<_AlpnSelectNative>>,
  ffi.Pointer<ffi.Void>,
);

final _boringSslServerSessions = <int, _BoringSslQuicServerState>{};

base class _SslQuicMethod extends ffi.Struct {
  external ffi.Pointer<ffi.NativeFunction<_SetSecretNative>> setReadSecret;
  external ffi.Pointer<ffi.NativeFunction<_SetSecretNative>> setWriteSecret;
  external ffi.Pointer<ffi.NativeFunction<_AddHandshakeDataNative>>
      addHandshakeData;
  external ffi.Pointer<ffi.NativeFunction<_FlushFlightNative>> flushFlight;
  external ffi.Pointer<ffi.NativeFunction<_SendAlertNative>> sendAlert;
}

class _QuicInspectorServer {
  _QuicInspectorServer({
    required this.crypto,
    required String certificateFile,
    required String privateKeyFile,
    required int initialMaxData,
    required int initialMaxStreamData,
    required int maxIdleTimeout,
    required this.terminateFirstClientStream,
    required this.completeResponseResetNoError,
    required this.keyUpdateAfterHandshake,
    required this.closeAfterHandshake,
    required this.probeClientClose,
    required this.versionNegotiation,
    required this.versionNegotiationIncludesV1,
    required this.statelessResetAfterHandshake,
    required this.rotateConnectionId,
    required this.pathChallengeAfterHandshake,
    required this.newToken,
    required this.retry,
    required this.rejectResumedEarlyData,
    required this.dynamicQpackResponse,
    required this.redirectLocation,
    required this.responseAltSvc,
    required this.goawayAfterFirstRequest,
    required this.rejectFirstRequestWithGoaway,
    required this.echoApplicationData,
    required this.sendFlowControlViolation,
    required this.preferredAddressPort,
  }) : tls = _BoringSslQuicServer(
          crypto: crypto,
          certificateFile: certificateFile,
          privateKeyFile: privateKeyFile,
          initialMaxData: initialMaxData,
          initialMaxStreamData: initialMaxStreamData,
          maxIdleTimeout: maxIdleTimeout,
        );

  final _BoringSslCrypto crypto;
  final _BoringSslQuicServer tls;
  final bool terminateFirstClientStream;
  final bool completeResponseResetNoError;
  final bool keyUpdateAfterHandshake;
  final bool closeAfterHandshake;
  final bool probeClientClose;
  final bool versionNegotiation;
  final bool versionNegotiationIncludesV1;
  final bool statelessResetAfterHandshake;
  final bool rotateConnectionId;
  final bool pathChallengeAfterHandshake;
  final bool newToken;
  final bool retry;
  final bool rejectResumedEarlyData;
  final bool dynamicQpackResponse;
  final String? redirectLocation;
  final String? responseAltSvc;
  final bool goawayAfterFirstRequest;
  final bool rejectFirstRequestWithGoaway;
  final bool echoApplicationData;
  final bool sendFlowControlViolation;
  final int? preferredAddressPort;
  final _connections = <String, _QuicInspectorConnection>{};
  final _versionNegotiationSent = <String>{};
  final _retryStates = <String, _InspectorRetryState>{};
  final _pendingWrites =
      <RawDatagramSocket, Queue<(Uint8List, InternetAddress, int)>>{};
  final _writeTimers = <RawDatagramSocket, Timer>{};
  var _connectionCount = 0;

  void _send(
    RawDatagramSocket socket,
    Uint8List data,
    InternetAddress address,
    int port,
  ) {
    final pending = _pendingWrites.putIfAbsent(
      socket,
      () => Queue<(Uint8List, InternetAddress, int)>(),
    );
    pending.add((data, address, port));
    _scheduleWrite(socket);
  }

  void _scheduleWrite(RawDatagramSocket socket) {
    if (_writeTimers.containsKey(socket)) return;
    _writeTimers[socket] = Timer(const Duration(milliseconds: 1), () {
      _writeTimers.remove(socket);
      flushWrites(socket);
    });
  }

  void flushWrites(RawDatagramSocket socket) {
    final pending = _pendingWrites[socket];
    if (pending == null) {
      socket.writeEventsEnabled = false;
      return;
    }
    var budget = 8;
    while (pending.isNotEmpty && budget-- != 0) {
      final datagram = pending.first;
      if (socket.send(datagram.$1, datagram.$2, datagram.$3) <= 0) {
        socket.writeEventsEnabled = true;
        return;
      }
      pending.removeFirst();
    }
    if (pending.isEmpty) {
      socket.writeEventsEnabled = false;
    } else {
      _scheduleWrite(socket);
    }
  }

  _PacketProtection? protectionForIncomingHandshake(Uint8List dcid) {
    return _connectionByServerCid(dcid)?.incomingProtection(
      _QuicEncryptionLevel.handshake,
    );
  }

  _PacketProtection? protectionForIncomingEarlyData(Uint8List dcid) {
    return _connectionByServerCid(dcid)?.incomingProtection(
      _QuicEncryptionLevel.earlyData,
    );
  }

  _ShortHeaderProtectionMatch? shortHeaderProtection(
    Uint8List datagram,
    int destinationConnectionIdOffset,
  ) {
    for (final connection in _connections.values) {
      for (final dcid in connection.serverConnectionIds) {
        if (destinationConnectionIdOffset + dcid.length > datagram.length) {
          continue;
        }
        var matches = true;
        for (var i = 0; i < dcid.length; i++) {
          if (datagram[destinationConnectionIdOffset + i] != dcid[i]) {
            matches = false;
            break;
          }
        }
        if (!matches) continue;

        final protection = connection.incomingProtection(
          _QuicEncryptionLevel.application,
        );
        if (protection == null) return null;
        return _ShortHeaderProtectionMatch(
          destinationConnectionId: dcid,
          protection: protection,
        );
      }
    }
    return null;
  }

  void handlePacket(
    RawDatagramSocket receivingSocket,
    Datagram datagram,
    _InspectedPacket packet,
  ) {
    final endpoint = '${datagram.address.address}:${datagram.port}';
    if (packet.level == _QuicEncryptionLevel.initial &&
        packet.initialToken.isNotEmpty) {
      print('  client Initial token=${_hex(packet.initialToken)}');
    }
    if (versionNegotiation &&
        packet.level == _QuicEncryptionLevel.initial &&
        _versionNegotiationSent.add(endpoint)) {
      final response = _buildVersionNegotiationPacket(
        packet,
        includeVersion1: versionNegotiationIncludesV1,
      );
      _send(receivingSocket, response, datagram.address, datagram.port);
      print('  server => VERSION_NEGOTIATION '
          'includesV1=$versionNegotiationIncludesV1 length=${response.length}');
      return;
    }
    if (retry && packet.level == _QuicEncryptionLevel.initial) {
      final state = _retryStates[endpoint];
      if (state == null) {
        final serverConnectionId = Uint8List.fromList(
          const [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7],
        );
        final token = Uint8List.fromList(utf8.encode('inspector retry token'));
        final retryState = _InspectorRetryState(
          originalDestinationConnectionId: packet.destinationConnectionId,
          serverConnectionId: serverConnectionId,
          token: token,
        );
        _retryStates[endpoint] = retryState;
        final response = _buildRetryPacket(
          crypto,
          packet,
          serverConnectionId,
          token,
        );
        _send(receivingSocket, response, datagram.address, datagram.port);
        print('  server => RETRY token.length=${token.length} '
            'length=${response.length} '
            'scid=${_hex(serverConnectionId)}');
        return;
      }
      if (_hex(packet.destinationConnectionId) !=
              _hex(state.serverConnectionId) ||
          _hex(packet.initialToken) != _hex(state.token)) {
        print('  ERROR retried Initial has wrong DCID or token');
        return;
      }
      print('  retried Initial token validated');
    }
    final connection = _connectionFor(datagram, packet);
    final responses = connection.handlePacket(packet);
    for (final response in responses) {
      _send(receivingSocket, response, datagram.address, datagram.port);
      print('sent udp.length=${response.length} to '
          '${datagram.address.address}:${datagram.port} '
          'via serverPort=${receivingSocket.port} '
          'prefix=${_formatBytes(response.take(12).toList())}');
    }
  }

  _QuicInspectorConnection _connectionFor(
    Datagram datagram,
    _InspectedPacket packet,
  ) {
    final key = '${datagram.address.address}:${datagram.port}';
    final existing = _connectionByServerCid(packet.destinationConnectionId);
    if (existing != null) {
      _connections[key] = existing;
      return existing;
    }
    return _connections.putIfAbsent(key, () {
      final connectionNumber = _connectionCount++;
      final retryState = _retryStates[key];
      final originalDestinationConnectionId =
          retryState?.originalDestinationConnectionId ??
              packet.destinationConnectionId;
      final serverConnectionId =
          retryState?.serverConnectionId ?? packet.destinationConnectionId;
      return _QuicInspectorConnection(
        crypto: crypto,
        tls: tls.createSession(
          originalDestinationConnectionId: originalDestinationConnectionId,
          initialSourceConnectionId: serverConnectionId,
          retrySourceConnectionId: retryState?.serverConnectionId,
          preferredIpv4Port: preferredAddressPort,
          enableEarlyData: !rejectResumedEarlyData || connectionNumber == 0,
        ),
        originalDestinationConnectionId: originalDestinationConnectionId,
        initialKeysConnectionId: packet.destinationConnectionId,
        serverConnectionId: serverConnectionId,
        clientConnectionId: packet.sourceConnectionId,
        terminateFirstClientStream: terminateFirstClientStream,
        completeResponseResetNoError: completeResponseResetNoError,
        keyUpdateAfterHandshake: keyUpdateAfterHandshake,
        closeAfterHandshake: closeAfterHandshake,
        probeClientClose: probeClientClose,
        statelessResetAfterHandshake: statelessResetAfterHandshake,
        rotateConnectionId: rotateConnectionId,
        pathChallengeAfterHandshake: pathChallengeAfterHandshake,
        newToken: newToken,
        dynamicQpackResponse: dynamicQpackResponse,
        redirectLocation: redirectLocation,
        responseAltSvc: responseAltSvc,
        goawayAfterFirstRequest:
            goawayAfterFirstRequest && connectionNumber == 0,
        rejectFirstRequestWithGoaway:
            rejectFirstRequestWithGoaway && connectionNumber == 0,
        echoApplicationData: echoApplicationData,
        sendFlowControlViolation: sendFlowControlViolation,
        preferredServerConnectionId: preferredAddressPort == null
            ? null
            : Uint8List.fromList(_preferredServerConnectionId),
      );
    });
  }

  _QuicInspectorConnection? _connectionByServerCid(Uint8List dcid) {
    final hex = _hex(dcid);
    for (final connection in _connections.values) {
      if (connection.serverConnectionIds.any((cid) => _hex(cid) == hex)) {
        return connection;
      }
    }
    return null;
  }
}

class _InspectorRetryState {
  const _InspectorRetryState({
    required this.originalDestinationConnectionId,
    required this.serverConnectionId,
    required this.token,
  });

  final Uint8List originalDestinationConnectionId;
  final Uint8List serverConnectionId;
  final Uint8List token;
}

class _QuicInspectorConnection {
  _QuicInspectorConnection({
    required this.crypto,
    required this.tls,
    required this.originalDestinationConnectionId,
    required this.initialKeysConnectionId,
    required this.serverConnectionId,
    required this.clientConnectionId,
    required this.terminateFirstClientStream,
    required this.completeResponseResetNoError,
    required this.keyUpdateAfterHandshake,
    required this.closeAfterHandshake,
    required this.probeClientClose,
    required this.statelessResetAfterHandshake,
    required this.rotateConnectionId,
    required this.pathChallengeAfterHandshake,
    required this.newToken,
    required this.dynamicQpackResponse,
    required this.redirectLocation,
    required this.responseAltSvc,
    required this.goawayAfterFirstRequest,
    required this.rejectFirstRequestWithGoaway,
    required this.echoApplicationData,
    required this.sendFlowControlViolation,
    required this.preferredServerConnectionId,
  });

  final _BoringSslCrypto crypto;
  final _BoringSslQuicServerSession tls;
  final Uint8List originalDestinationConnectionId;
  final Uint8List initialKeysConnectionId;
  final Uint8List serverConnectionId;
  final Uint8List clientConnectionId;
  final bool terminateFirstClientStream;
  final bool completeResponseResetNoError;
  final bool keyUpdateAfterHandshake;
  final bool closeAfterHandshake;
  final bool probeClientClose;
  final bool statelessResetAfterHandshake;
  final bool rotateConnectionId;
  final bool pathChallengeAfterHandshake;
  final bool newToken;
  final bool dynamicQpackResponse;
  final String? redirectLocation;
  final String? responseAltSvc;
  final bool goawayAfterFirstRequest;
  final bool rejectFirstRequestWithGoaway;
  final bool echoApplicationData;
  final bool sendFlowControlViolation;
  final Uint8List? preferredServerConnectionId;
  final _alternateServerConnectionId = Uint8List.fromList(
    const [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7],
  );
  final _statelessResetToken = Uint8List.fromList(
    const [
      0xb0,
      0xb1,
      0xb2,
      0xb3,
      0xb4,
      0xb5,
      0xb6,
      0xb7,
      0xb8,
      0xb9,
      0xba,
      0xbb,
      0xbc,
      0xbd,
      0xbe,
      0xbf,
    ],
  );
  final _pathChallenge = Uint8List.fromList(
    const [0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7],
  );
  final _newToken = Uint8List.fromList(
    utf8.encode('inspector-new-token'),
  );
  final _cryptoWriteOffsets = <_QuicEncryptionLevel, int>{
    _QuicEncryptionLevel.initial: 0,
    _QuicEncryptionLevel.handshake: 0,
    _QuicEncryptionLevel.application: 0,
  };
  final _cryptoReadStreams = <_QuicEncryptionLevel, _CryptoStreamReassembler>{
    _QuicEncryptionLevel.initial: _CryptoStreamReassembler(),
    _QuicEncryptionLevel.handshake: _CryptoStreamReassembler(),
    _QuicEncryptionLevel.application: _CryptoStreamReassembler(),
  };
  final _nextPacketNumbers = <_QuicEncryptionLevel, int>{
    _QuicEncryptionLevel.initial: 0,
    _QuicEncryptionLevel.handshake: 0,
    _QuicEncryptionLevel.application: 0,
  };
  final _receivedPacketNumbers = <_QuicEncryptionLevel, SplayTreeSet<int>>{
    _QuicEncryptionLevel.initial: SplayTreeSet<int>(),
    _QuicEncryptionLevel.earlyData: SplayTreeSet<int>(),
    _QuicEncryptionLevel.handshake: SplayTreeSet<int>(),
    _QuicEncryptionLevel.application: SplayTreeSet<int>(),
  };
  bool _sentPostHandshakeData = false;
  bool _sentKeyUpdateData = false;
  bool _terminatedFirstClientStream = false;
  bool _sentCompleteResponseResetNoError = false;
  bool _probedClientClose = false;
  bool _sentConnectionId = false;
  bool _sentStatelessReset = false;
  bool _sentDynamicQpackResponse = false;
  bool _sentRedirectResponse = false;
  bool _sentAltSvcResponse = false;
  bool _sentGoaway = false;
  int _controlStreamWriteOffset = 0;
  _PacketProtection? _applicationWriteProtection;
  bool _applicationWriteKeyPhase = false;

  Iterable<Uint8List> get serverConnectionIds sync* {
    yield serverConnectionId;
    if (preferredServerConnectionId != null) {
      yield preferredServerConnectionId!;
    }
    if (_sentConnectionId) {
      yield _alternateServerConnectionId;
    }
  }

  _PacketProtection? incomingProtection(_QuicEncryptionLevel level) {
    final secret = tls.readSecrets[level];
    if (secret == null) return null;
    return crypto.protectionForSecret(secret);
  }

  List<Uint8List> handlePacket(_InspectedPacket packet) {
    final receivedPacketNumbers = _receivedPacketNumbers[packet.level]!
      ..add(packet.packetNumber);
    final firstTracked = packet.packetNumber - 4095;
    while (receivedPacketNumbers.isNotEmpty &&
        receivedPacketNumbers.first < firstTracked) {
      receivedPacketNumbers.remove(receivedPacketNumbers.first);
    }
    for (final frame in packet.cryptoFrames) {
      print('  server tls <= ${packet.level.name} CRYPTO '
          'offset=${frame.offset} length=${frame.data.length}');
      final ready = _cryptoReadStreams[packet.level]!.add(
        frame.offset,
        frame.data,
      );
      for (final data in ready) {
        tls.provideQuicData(packet.level, data);
      }
    }
    tls.driveHandshake();

    final responses = <Uint8List>[];
    if (packet.level == _QuicEncryptionLevel.earlyData) {
      print('  server <= 0-RTT accepted=${tls.earlyDataAccepted} '
          'streams=${packet.streamFrames.length}');
      if (tls.writeSecrets.containsKey(_QuicEncryptionLevel.application)) {
        final frames = BytesBuilder(copy: false);
        _appendAckFrame(frames, packet.packetNumber);
        responses.add(_buildShortHeaderPacket(frames.takeBytes()));
      }
    } else if (packet.level == _QuicEncryptionLevel.application &&
        packet.streamFrames.isNotEmpty) {
      print('  server <= 1-RTT streams=${packet.streamFrames.length}');
    }
    for (final challenge in packet.pathChallenges) {
      final frames = BytesBuilder(copy: false);
      _appendPathResponseFrame(frames, challenge);
      print('  server 1-rtt => PATH_RESPONSE data=${_hex(challenge)}');
      responses.add(_buildShortHeaderPacket(frames.takeBytes()));
    }
    final pending = tls.takeCryptoData();
    var acknowledgedAtPacketLevel = false;
    for (final data in pending) {
      print('  server tls => ${data.level.name} CRYPTO '
          'length=${data.data.length}');
      acknowledgedAtPacketLevel |= data.level == packet.level;
      responses.addAll(_packetizeCrypto(data.level, data.data, packet));
    }
    if (!acknowledgedAtPacketLevel &&
        packet.cryptoFrames.isNotEmpty &&
        packet.level != _QuicEncryptionLevel.application) {
      final frames = BytesBuilder(copy: false);
      _appendAckFrame(frames, packet.packetNumber);
      responses.add(_buildProtectedPacket(packet.level, frames.takeBytes()));
    }
    if (!_sentPostHandshakeData &&
        tls.handshakeComplete &&
        tls.writeSecrets.containsKey(_QuicEncryptionLevel.application)) {
      _sentPostHandshakeData = true;
      final data = _buildPostHandshakeDataPacket();
      print('  server 1-rtt => HANDSHAKE_DONE + h3 SETTINGS '
          'length=${data.length}');
      responses.add(data);
      if (sendFlowControlViolation) {
        final frames = BytesBuilder(copy: false);
        _appendStreamFrame(
          frames,
          streamId: 1,
          offset: 2 * 1024 * 1024,
          data: Uint8List.fromList(const [0x01]),
          fin: false,
        );
        final violation = _buildShortHeaderPacket(frames.takeBytes());
        print('  server 1-rtt => STREAM flow-control violation '
            'id=1 offset=${2 * 1024 * 1024} length=1');
        responses.add(violation);
      }
      if (closeAfterHandshake) {
        final frames = BytesBuilder(copy: false);
        _appendVarInt(frames, 0x1d);
        _appendVarInt(frames, 0x107);
        final reason = Uint8List.fromList(utf8.encode('inspector close'));
        _appendVarInt(frames, reason.length);
        frames.add(reason);
        final close = _buildShortHeaderPacket(frames.takeBytes());
        print('  server 1-rtt => CONNECTION_CLOSE application '
            'error=263 reason="inspector close"');
        responses.add(close);
      }
      if (keyUpdateAfterHandshake && !_sentKeyUpdateData) {
        _sentKeyUpdateData = true;
        _applicationWriteProtection = crypto.nextProtectionForSecret(
          tls.writeSecrets[_QuicEncryptionLevel.application]!,
        );
        _applicationWriteKeyPhase = true;
        final frames = BytesBuilder(copy: false);
        _appendStreamFrame(
          frames,
          streamId: 7,
          offset: 0,
          data: Uint8List.fromList(utf8.encode('key-update')),
          fin: true,
        );
        final updated = _buildShortHeaderPacket(frames.takeBytes());
        print('  server 1-rtt => STREAM id=7 keyPhase=1 '
            'length=${updated.length}');
        responses.add(updated);
      }
      if ((statelessResetAfterHandshake || rotateConnectionId) &&
          !_sentConnectionId) {
        _sentConnectionId = true;
        final frames = BytesBuilder(copy: false);
        _appendNewConnectionIdFrame(
          frames,
          sequence: 1,
          retirePriorTo: rotateConnectionId ? 1 : 0,
          connectionId: _alternateServerConnectionId,
          statelessResetToken: _statelessResetToken,
        );
        final packet = _buildShortHeaderPacket(frames.takeBytes());
        print('  server 1-rtt => NEW_CONNECTION_ID sequence=1 '
            'retirePriorTo=${rotateConnectionId ? 1 : 0} '
            'cid=${_hex(_alternateServerConnectionId)}');
        responses.add(packet);
      }
      if (pathChallengeAfterHandshake) {
        final frames = BytesBuilder(copy: false);
        _appendPathChallengeFrame(frames, _pathChallenge);
        print('  server 1-rtt => PATH_CHALLENGE '
            'data=${_hex(_pathChallenge)}');
        responses.add(_buildShortHeaderPacket(frames.takeBytes()));
      }
    }
    if (statelessResetAfterHandshake &&
        _sentConnectionId &&
        !_sentStatelessReset &&
        packet.level == _QuicEncryptionLevel.application) {
      _sentStatelessReset = true;
      final reset = Uint8List(32)..[0] = 0x40;
      for (var i = 1; i < reset.length - _statelessResetToken.length; i++) {
        reset[i] = (i * 37) & 0xff;
      }
      reset.setRange(
        reset.length - _statelessResetToken.length,
        reset.length,
        _statelessResetToken,
      );
      print('  server => STATELESS_RESET token=${_hex(_statelessResetToken)}');
      responses.add(reset);
    }
    if (packet.level == _QuicEncryptionLevel.application &&
        packet.blockedFrames.isNotEmpty) {
      final frames = BytesBuilder(copy: false);
      _appendAckFrame(frames, packet.packetNumber);
      for (final blocked in packet.blockedFrames) {
        final streamId = blocked.streamId;
        if (streamId == null) {
          _appendMaxDataFrame(frames, 1048576);
          print('  server 1-rtt => MAX_DATA 1048576');
        } else {
          _appendMaxStreamDataFrame(frames, streamId, 524288);
          print('  server 1-rtt => MAX_STREAM_DATA id=$streamId 524288');
        }
      }
      responses.add(_buildShortHeaderPacket(frames.takeBytes()));
    }
    if (echoApplicationData &&
        packet.level == _QuicEncryptionLevel.application &&
        tls.writeSecrets.containsKey(_QuicEncryptionLevel.application) &&
        (packet.streamFrames.isNotEmpty || packet.datagrams.isNotEmpty)) {
      responses.addAll(_buildApplicationEchoPackets(packet));
    }
    if (dynamicQpackResponse &&
        !_sentDynamicQpackResponse &&
        !rejectFirstRequestWithGoaway &&
        (packet.level == _QuicEncryptionLevel.application ||
            packet.level == _QuicEncryptionLevel.earlyData) &&
        tls.writeSecrets.containsKey(_QuicEncryptionLevel.application)) {
      _StreamFrame? requestFrame;
      for (final frame in packet.streamFrames) {
        if ((frame.streamId & 0x03) == 0 && frame.length != 0) {
          requestFrame = frame;
          break;
        }
      }
      if (requestFrame != null) {
        _sentDynamicQpackResponse = true;
        responses.add(_buildDynamicQpackResponse(
          requestFrame.streamId,
          packet.packetNumber,
        ));
      }
    }
    if (redirectLocation != null &&
        !_sentRedirectResponse &&
        (packet.level == _QuicEncryptionLevel.application ||
            packet.level == _QuicEncryptionLevel.earlyData) &&
        tls.writeSecrets.containsKey(_QuicEncryptionLevel.application)) {
      _StreamFrame? requestFrame;
      for (final frame in packet.streamFrames) {
        if ((frame.streamId & 0x03) == 0 && frame.length != 0) {
          requestFrame = frame;
          break;
        }
      }
      if (requestFrame != null) {
        _sentRedirectResponse = true;
        responses.add(_buildRedirectResponse(
          requestFrame.streamId,
          packet.packetNumber,
          redirectLocation!,
        ));
      }
    }
    if (responseAltSvc != null &&
        !_sentAltSvcResponse &&
        (packet.level == _QuicEncryptionLevel.application ||
            packet.level == _QuicEncryptionLevel.earlyData) &&
        tls.writeSecrets.containsKey(_QuicEncryptionLevel.application)) {
      _StreamFrame? requestFrame;
      for (final frame in packet.streamFrames) {
        if ((frame.streamId & 0x03) == 0 && frame.length != 0) {
          requestFrame = frame;
          break;
        }
      }
      if (requestFrame != null) {
        _sentAltSvcResponse = true;
        responses.add(_buildAltSvcResponse(
          requestFrame.streamId,
          packet.packetNumber,
          responseAltSvc!,
        ));
      }
    }
    if ((goawayAfterFirstRequest || rejectFirstRequestWithGoaway) &&
        !_sentGoaway &&
        packet.level == _QuicEncryptionLevel.application) {
      _StreamFrame? requestFrame;
      for (final frame in packet.streamFrames) {
        if ((frame.streamId & 0x03) == 0 && frame.length != 0) {
          requestFrame = frame;
          break;
        }
      }
      if (requestFrame != null) {
        _sentGoaway = true;
        final id = rejectFirstRequestWithGoaway
            ? requestFrame.streamId
            : requestFrame.streamId + 4;
        responses.add(_buildGoawayPacket(id, packet.packetNumber));
        print('  server 1-rtt => h3 GOAWAY id=$id');
      }
    }
    if (completeResponseResetNoError &&
        !_sentCompleteResponseResetNoError &&
        packet.level == _QuicEncryptionLevel.application &&
        tls.writeSecrets.containsKey(_QuicEncryptionLevel.application)) {
      _StreamFrame? requestFrame;
      for (final frame in packet.streamFrames) {
        if ((frame.streamId & 0x03) == 0 && frame.length != 0) {
          requestFrame = frame;
          break;
        }
      }
      if (requestFrame != null) {
        _sentCompleteResponseResetNoError = true;
        // Required Insert Count = 0, Base = 0, static :status 200 (index 25),
        // and static content-length: 0 (index 4).
        final response = Uint8List.fromList(
          const [0x01, 0x04, 0x00, 0x00, 0xd9, 0xc4],
        );
        final frames = BytesBuilder(copy: false);
        _appendAckFrame(frames, packet.packetNumber);
        _appendStreamFrame(
          frames,
          streamId: requestFrame.streamId,
          offset: 0,
          data: response,
          fin: false,
        );
        _appendResetStreamFrame(
          frames,
          requestFrame.streamId,
          0x0100,
          response.length,
        );
        _appendStopSendingFrame(frames, requestFrame.streamId, 0x0100);
        print('  server 1-rtt => complete response then RESET_STREAM '
            'id=${requestFrame.streamId} error=256 finalSize=${response.length}');
        print('  server 1-rtt => STOP_SENDING id=${requestFrame.streamId} '
            'error=256');
        responses.add(_buildShortHeaderPacket(frames.takeBytes()));
      }
    }
    if (terminateFirstClientStream &&
        !_terminatedFirstClientStream &&
        packet.level == _QuicEncryptionLevel.application) {
      _StreamFrame? requestFrame;
      for (final frame in packet.streamFrames) {
        if ((frame.streamId & 0x03) == 0) {
          requestFrame = frame;
          break;
        }
      }
      if (requestFrame != null) {
        _terminatedFirstClientStream = true;
        final frames = BytesBuilder(copy: false);
        _appendAckFrame(frames, packet.packetNumber);
        _appendResetStreamFrame(frames, requestFrame.streamId, 42, 0);
        _appendStopSendingFrame(frames, requestFrame.streamId, 43);
        _appendResetStreamFrame(frames, 7, 44, 0);
        print('  server 1-rtt => RESET_STREAM id=${requestFrame.streamId} '
            'error=42 finalSize=0');
        print('  server 1-rtt => STOP_SENDING id=${requestFrame.streamId} '
            'error=43');
        print('  server 1-rtt => RESET_STREAM id=7 error=44 finalSize=0');
        responses.add(_buildShortHeaderPacket(frames.takeBytes()));
      }
    }
    if (probeClientClose && packet.connectionClose && !_probedClientClose) {
      _probedClientClose = true;
      final frames = BytesBuilder(copy: false)..addByte(0x01);
      print('  server 1-rtt => PING after client CONNECTION_CLOSE');
      responses.add(_buildShortHeaderPacket(frames.takeBytes()));
    }
    return responses;
  }

  List<Uint8List> _buildApplicationEchoPackets(_InspectedPacket packet) {
    final responses = <Uint8List>[];
    var ackPending = true;
    var streamCount = 0;
    for (final frame in packet.streamFrames) {
      if ((frame.streamId & 0x02) != 0) continue;
      final payload = BytesBuilder(copy: false);
      if (ackPending) {
        _appendAckRangesFrame(payload, _receivedPacketNumbers[packet.level]!);
        ackPending = false;
      }
      _appendStreamFrame(
        payload,
        streamId: frame.streamId,
        offset: frame.offset,
        data: frame.data,
        fin: frame.fin,
      );
      responses.add(_buildShortHeaderPacket(payload.takeBytes()));
      streamCount++;
    }
    for (final datagram in packet.datagrams) {
      final payload = BytesBuilder(copy: false);
      if (ackPending) {
        _appendAckRangesFrame(payload, _receivedPacketNumbers[packet.level]!);
        ackPending = false;
      }
      _appendDatagramFrame(payload, datagram);
      responses.add(_buildShortHeaderPacket(payload.takeBytes()));
    }
    if (ackPending) {
      final ack = BytesBuilder(copy: false);
      _appendAckRangesFrame(ack, _receivedPacketNumbers[packet.level]!);
      responses.add(_buildShortHeaderPacket(ack.takeBytes()));
    }
    print('  server 1-rtt => echo streams=$streamCount '
        'datagrams=${packet.datagrams.length}');
    return responses;
  }

  List<Uint8List> _packetizeCrypto(
    _QuicEncryptionLevel level,
    Uint8List data,
    _InspectedPacket ackedPacket,
  ) {
    final responses = <Uint8List>[];
    var offset = 0;
    while (offset < data.length) {
      final maxCryptoBytes = level == _QuicEncryptionLevel.initial ? 900 : 1000;
      final chunkLength =
          (data.length - offset).clamp(0, maxCryptoBytes).toInt();
      final cryptoOffset = _cryptoWriteOffsets[level]!;
      final frames = BytesBuilder(copy: false);
      if (offset == 0 && level == ackedPacket.level) {
        _appendAckFrame(frames, ackedPacket.packetNumber);
      }
      _appendCryptoFrame(
        frames,
        cryptoOffset,
        Uint8List.sublistView(data, offset, offset + chunkLength),
      );
      _cryptoWriteOffsets[level] = cryptoOffset + chunkLength;
      offset += chunkLength;

      final plaintext = frames.takeBytes();
      if (level == _QuicEncryptionLevel.application) {
        responses.add(_buildShortHeaderPacket(plaintext));
      } else {
        responses.add(_buildProtectedPacket(level, plaintext));
      }
    }
    return responses;
  }

  Uint8List _buildProtectedPacket(
    _QuicEncryptionLevel level,
    Uint8List plaintext,
  ) {
    final packetNumber = _nextPacketNumbers[level]!;
    _nextPacketNumbers[level] = packetNumber + 1;
    final packetNumberLength = 2;
    final protection = level == _QuicEncryptionLevel.initial
        ? _PacketProtection(
            level: level,
            keys: crypto.initialKeys(
              initialKeysConnectionId,
              client: false,
            ),
            cipherId: _tlsAes128GcmSha256,
          )
        : crypto.protectionForSecret(tls.writeSecrets[level]!);

    var body = plaintext;
    var header = _longHeader(
      level: level,
      packetNumber: packetNumber,
      packetNumberLength: packetNumberLength,
      protectedPayloadLength: body.length + _quicTagLength,
    );
    while (level == _QuicEncryptionLevel.initial &&
        header.length + body.length + _quicTagLength <
            _quicMinInitialDatagramSize) {
      body = Uint8List.fromList([...body, 0]);
      header = _longHeader(
        level: level,
        packetNumber: packetNumber,
        packetNumberLength: packetNumberLength,
        protectedPayloadLength: body.length + _quicTagLength,
      );
    }

    final aad = Uint8List.fromList(header);
    final ciphertext = crypto.seal(
      key: protection.keys.key,
      nonce: protection.keys.nonce(packetNumber),
      plaintext: body,
      aad: aad,
      cipherId: protection.cipherId,
    );
    final packet = Uint8List.fromList([...header, ...ciphertext]);
    final packetNumberOffset = header.length - packetNumberLength;
    final sampleOffset = packetNumberOffset + 4;
    final sample =
        Uint8List.sublistView(packet, sampleOffset, sampleOffset + 16);
    final mask = crypto.aesMask(protection.keys.hp, sample);
    packet[0] ^= mask[0] & 0x0f;
    for (var i = 0; i < packetNumberLength; i++) {
      packet[packetNumberOffset + i] ^= mask[i + 1];
    }
    return packet;
  }

  Uint8List _longHeader({
    required _QuicEncryptionLevel level,
    required int packetNumber,
    required int packetNumberLength,
    required int protectedPayloadLength,
  }) {
    final packetType = switch (level) {
      _QuicEncryptionLevel.initial => _quicPacketTypeInitial,
      _QuicEncryptionLevel.handshake => _quicPacketTypeHandshake,
      _ => throw UnsupportedError('cannot send $level as a long header'),
    };
    final bytes = BytesBuilder(copy: false)
      ..addByte(0xc0 | (packetType << 4) | (packetNumberLength - 1))
      ..add(_uint32Bytes(_quicVersion1))
      ..addByte(clientConnectionId.length)
      ..add(clientConnectionId)
      ..addByte(serverConnectionId.length)
      ..add(serverConnectionId);
    if (level == _QuicEncryptionLevel.initial) {
      _appendVarInt(bytes, 0);
    }
    _appendVarInt(bytes, packetNumberLength + protectedPayloadLength);
    for (var i = packetNumberLength - 1; i >= 0; i--) {
      bytes.addByte((packetNumber >> (8 * i)) & 0xff);
    }
    return bytes.takeBytes();
  }

  Uint8List _buildPostHandshakeDataPacket() {
    final plaintext = BytesBuilder(copy: false)
      ..addByte(0x1e)
      ..add(_buildHttp3ControlStreamSettings());
    if (newToken) {
      _appendNewTokenFrame(plaintext, _newToken);
      print('  server 1-rtt => NEW_TOKEN token=${_hex(_newToken)}');
    }
    return _buildShortHeaderPacket(plaintext.takeBytes());
  }

  Uint8List _buildHttp3ControlStreamSettings() {
    final payload = BytesBuilder(copy: false);
    _appendVarInt(payload, 0x00);
    final settings = BytesBuilder(copy: false);
    if (dynamicQpackResponse) {
      _appendVarInt(settings, 0x01);
      _appendVarInt(settings, 220);
      _appendVarInt(settings, 0x07);
      _appendVarInt(settings, 1);
    }
    final encodedSettings = settings.takeBytes();
    _appendVarInt(payload, 0x04);
    _appendVarInt(payload, encodedSettings.length);
    payload.add(encodedSettings);

    final controlData = payload.takeBytes();
    final frames = BytesBuilder(copy: false);
    _appendStreamFrame(
      frames,
      streamId: 3,
      offset: 0,
      data: controlData,
      fin: false,
    );
    _controlStreamWriteOffset = controlData.length;
    return frames.takeBytes();
  }

  Uint8List _buildGoawayPacket(int id, int acknowledgedPacketNumber) {
    final payload = BytesBuilder(copy: false);
    _appendVarInt(payload, 0x07);
    final encodedId = BytesBuilder(copy: false);
    _appendVarInt(encodedId, id);
    final idBytes = encodedId.takeBytes();
    _appendVarInt(payload, idBytes.length);
    payload.add(idBytes);
    final data = payload.takeBytes();

    final frames = BytesBuilder(copy: false);
    _appendAckFrame(frames, acknowledgedPacketNumber);
    _appendStreamFrame(
      frames,
      streamId: 3,
      offset: _controlStreamWriteOffset,
      data: data,
      fin: false,
    );
    _controlStreamWriteOffset += data.length;
    return _buildShortHeaderPacket(frames.takeBytes());
  }

  Uint8List _buildDynamicQpackResponse(
    int requestStreamId,
    int acknowledgedPacketNumber,
  ) {
    final frames = BytesBuilder(copy: false);
    _appendAckFrame(frames, acknowledgedPacketNumber);

    // Deliver the blocked field section first. The client can only decode its
    // dynamic server header after it processes the encoder stream below.
    final headerBlock = BytesBuilder(copy: false)
      ..add([0x02, 0x00, 0xd9, 0x80]);
    for (final cookie in const ['a=1; Path=/', 'b=2; HttpOnly']) {
      final value = utf8.encode(cookie);
      // Literal field line with a static name reference to set-cookie (14).
      headerBlock
        ..add([0x7e, value.length])
        ..add(value);
    }
    final encodedHeaderBlock = headerBlock.takeBytes();
    final response = BytesBuilder(copy: false)..addByte(0x01);
    _appendVarInt(response, encodedHeaderBlock.length);
    response.add(encodedHeaderBlock);
    final body = Uint8List.fromList(utf8.encode('dynamic-qpack'));
    response.addByte(0x00);
    _appendVarInt(response, body.length);
    response.add(body);
    _appendStreamFrame(
      frames,
      streamId: requestStreamId,
      offset: 0,
      data: response.takeBytes(),
      fin: true,
    );

    final encoderStream = BytesBuilder(copy: false)
      ..addByte(0x02)
      ..add([0x3f, 0xbd, 0x01])
      // Insert with static name reference 92 ("server").
      ..add([0xff, 0x1d, 0x0f])
      ..add(utf8.encode('qpack-inspector'));
    _appendStreamFrame(
      frames,
      streamId: 7,
      offset: 0,
      data: encoderStream.takeBytes(),
      fin: false,
    );
    print('  server 1-rtt => dynamic QPACK response stream=$requestStreamId');
    return _buildShortHeaderPacket(frames.takeBytes());
  }

  Uint8List _buildRedirectResponse(
    int requestStreamId,
    int acknowledgedPacketNumber,
    String location,
  ) {
    final locationBytes = utf8.encode(location);
    if (locationBytes.length >= 127) {
      throw ArgumentError.value(
        location,
        'location',
        'Inspector redirect location must be shorter than 127 bytes',
      );
    }

    // Required Insert Count = 0, Base = 0, static :status 302 (index 66),
    // then a literal field line using static name "location" (index 12).
    final headerBlock = BytesBuilder(copy: false)
      ..add([0x00, 0x00, 0xff, 0x03, 0x5c, locationBytes.length])
      ..add(locationBytes);
    final encodedHeaders = headerBlock.takeBytes();
    final response = BytesBuilder(copy: false)..addByte(0x01);
    _appendVarInt(response, encodedHeaders.length);
    response.add(encodedHeaders);

    final frames = BytesBuilder(copy: false);
    _appendAckFrame(frames, acknowledgedPacketNumber);
    _appendStreamFrame(
      frames,
      streamId: requestStreamId,
      offset: 0,
      data: response.takeBytes(),
      fin: true,
    );
    print('  server 1-rtt => h3 redirect stream=$requestStreamId '
        'location=$location');
    return _buildShortHeaderPacket(frames.takeBytes());
  }

  Uint8List _buildAltSvcResponse(
    int requestStreamId,
    int acknowledgedPacketNumber,
    String altSvc,
  ) {
    final altSvcBytes = utf8.encode(altSvc);
    if (altSvcBytes.length >= 127) {
      throw ArgumentError.value(
        altSvc,
        'altSvc',
        'Inspector Alt-Svc value must be shorter than 127 bytes',
      );
    }

    // Static :status 200 (index 25), then a literal field line using the
    // static name "alt-svc" (index 83).
    final headerBlock = BytesBuilder(copy: false)
      ..add([0x00, 0x00, 0xd9, 0x5f, 0x44, altSvcBytes.length])
      ..add(altSvcBytes);
    final encodedHeaders = headerBlock.takeBytes();
    final body = utf8.encode('alt-svc-response');
    final response = BytesBuilder(copy: false)..addByte(0x01);
    _appendVarInt(response, encodedHeaders.length);
    response.add(encodedHeaders);
    response.addByte(0x00);
    _appendVarInt(response, body.length);
    response.add(body);

    final frames = BytesBuilder(copy: false);
    _appendAckFrame(frames, acknowledgedPacketNumber);
    _appendStreamFrame(
      frames,
      streamId: requestStreamId,
      offset: 0,
      data: response.takeBytes(),
      fin: true,
    );
    print('  server 1-rtt => h3 Alt-Svc response stream=$requestStreamId '
        'value=$altSvc');
    return _buildShortHeaderPacket(frames.takeBytes());
  }

  Uint8List _buildShortHeaderPacket(Uint8List plaintext) {
    final level = _QuicEncryptionLevel.application;
    final packetNumber = _nextPacketNumbers[level]!;
    _nextPacketNumbers[level] = packetNumber + 1;
    final packetNumberLength = 2;
    final protection = _applicationWriteProtection ??
        crypto.protectionForSecret(tls.writeSecrets[level]!);

    final header = BytesBuilder(copy: false)
      ..addByte(0x40 |
          (_applicationWriteKeyPhase ? 0x04 : 0) |
          (packetNumberLength - 1))
      ..add(clientConnectionId);
    for (var i = packetNumberLength - 1; i >= 0; i--) {
      header.addByte((packetNumber >> (8 * i)) & 0xff);
    }
    final aad = header.takeBytes();
    final packetNumberOffset = 1 + clientConnectionId.length;
    final sampleOffset = packetNumberOffset + 4;
    final minimumPlaintextLength =
        sampleOffset + 16 - aad.length - _quicTagLength;
    var body = plaintext;
    if (body.length < minimumPlaintextLength) {
      body = Uint8List(minimumPlaintextLength)
        ..setRange(0, plaintext.length, plaintext);
    }
    final ciphertext = crypto.seal(
      key: protection.keys.key,
      nonce: protection.keys.nonce(packetNumber),
      plaintext: body,
      aad: aad,
      cipherId: protection.cipherId,
    );
    final packet = Uint8List.fromList([...aad, ...ciphertext]);
    final sample =
        Uint8List.sublistView(packet, sampleOffset, sampleOffset + 16);
    final mask = crypto.aesMask(protection.keys.hp, sample);
    packet[0] ^= mask[0] & 0x1f;
    for (var i = 0; i < packetNumberLength; i++) {
      packet[packetNumberOffset + i] ^= mask[i + 1];
    }
    return packet;
  }
}

class _BoringSslQuicServer {
  _BoringSslQuicServer({
    required this.crypto,
    required this.certificateFile,
    required this.privateKeyFile,
    required this.initialMaxData,
    required this.initialMaxStreamData,
    required this.maxIdleTimeout,
  }) {
    _quicMethod =
        crypto.allocate(ffi.sizeOf<_SslQuicMethod>()).cast<_SslQuicMethod>();
    _quicMethod.ref
      ..setReadSecret =
          ffi.Pointer.fromFunction<_SetSecretNative>(_setReadSecret, 0)
      ..setWriteSecret =
          ffi.Pointer.fromFunction<_SetSecretNative>(_setWriteSecret, 0)
      ..addHandshakeData = ffi.Pointer.fromFunction<_AddHandshakeDataNative>(
        _addHandshakeData,
        0,
      )
      ..flushFlight =
          ffi.Pointer.fromFunction<_FlushFlightNative>(_flushFlight, 0)
      ..sendAlert = ffi.Pointer.fromFunction<_SendAlertNative>(_sendAlert, 0);
  }

  final _BoringSslCrypto crypto;
  final String certificateFile;
  final String privateKeyFile;
  final int initialMaxData;
  final int initialMaxStreamData;
  final int maxIdleTimeout;
  late final ffi.Pointer<_SslQuicMethod> _quicMethod;

  late final _TlsMethodDart _tlsMethod =
      crypto.sslLibrary.lookupFunction<_TlsMethodNative, _TlsMethodDart>(
    'TLS_method',
  );
  late final _SslCtxNewDart _sslCtxNew =
      crypto.sslLibrary.lookupFunction<_SslCtxNewNative, _SslCtxNewDart>(
    'SSL_CTX_new',
  );
  late final _SslCtxFreeDart _sslCtxFree =
      crypto.sslLibrary.lookupFunction<_SslCtxFreeNative, _SslCtxFreeDart>(
    'SSL_CTX_free',
  );
  late final _SslNewDart _sslNew =
      crypto.sslLibrary.lookupFunction<_SslNewNative, _SslNewDart>('SSL_new');
  late final _SslFreeDart _sslFree =
      crypto.sslLibrary.lookupFunction<_SslFreeNative, _SslFreeDart>(
    'SSL_free',
  );
  late final _SslVoidDart _sslSetAcceptState =
      crypto.sslLibrary.lookupFunction<_SslVoidNative, _SslVoidDart>(
    'SSL_set_accept_state',
  );
  late final _SslUint16ArgDart _sslSetMinProtoVersion =
      crypto.sslLibrary.lookupFunction<_SslUint16ArgNative, _SslUint16ArgDart>(
    'SSL_set_min_proto_version',
  );
  late final _SslUint16ArgDart _sslSetMaxProtoVersion =
      crypto.sslLibrary.lookupFunction<_SslUint16ArgNative, _SslUint16ArgDart>(
    'SSL_set_max_proto_version',
  );
  late final _SslSetQuicMethodDart _sslSetQuicMethod = crypto.sslLibrary
      .lookupFunction<_SslSetQuicMethodNative, _SslSetQuicMethodDart>(
          'SSL_set_quic_method');
  late final _SslVoidIntArgDart _sslSetQuicUseLegacyCodepoint = crypto
      .sslLibrary
      .lookupFunction<_SslVoidIntArgNative, _SslVoidIntArgDart>(
    'SSL_set_quic_use_legacy_codepoint',
  );
  late final _SslSetQuicTransportParamsDart _sslSetQuicTransportParams =
      crypto.sslLibrary.lookupFunction<_SslSetQuicTransportParamsNative,
          _SslSetQuicTransportParamsDart>('SSL_set_quic_transport_params');
  late final _SslSetBytesDart _sslCtxSetTicketKeys =
      crypto.sslLibrary.lookupFunction<_SslSetBytesNative, _SslSetBytesDart>(
    'SSL_CTX_set_tlsext_ticket_keys',
  );
  late final _SslVoidIntArgDart _sslSetEarlyDataEnabled = crypto.sslLibrary
      .lookupFunction<_SslVoidIntArgNative, _SslVoidIntArgDart>(
    'SSL_set_early_data_enabled',
  );
  late final _SslSetBytesDart _sslSetQuicEarlyDataContext =
      crypto.sslLibrary.lookupFunction<_SslSetBytesNative, _SslSetBytesDart>(
    'SSL_set_quic_early_data_context',
  );
  late final _SslIntDart _sslEarlyDataAccepted =
      crypto.sslLibrary.lookupFunction<_SslIntNative, _SslIntDart>(
    'SSL_early_data_accepted',
  );
  late final _SslProvideQuicDataDart _sslProvideQuicData = crypto.sslLibrary
      .lookupFunction<_SslProvideQuicDataNative, _SslProvideQuicDataDart>(
          'SSL_provide_quic_data');
  late final _SslIntDart _sslDoHandshake =
      crypto.sslLibrary.lookupFunction<_SslIntNative, _SslIntDart>(
    'SSL_do_handshake',
  );
  late final _SslIntDart _sslIsInitFinished =
      crypto.sslLibrary.lookupFunction<_SslIntNative, _SslIntDart>(
    'SSL_is_init_finished',
  );
  late final _SslGetErrorDart _sslGetError =
      crypto.sslLibrary.lookupFunction<_SslGetErrorNative, _SslGetErrorDart>(
    'SSL_get_error',
  );
  late final _SslUseCertChainFileDart _sslCtxUseCertificateChainFile = crypto
      .sslLibrary
      .lookupFunction<_SslUseCertChainFileNative, _SslUseCertChainFileDart>(
          'SSL_CTX_use_certificate_chain_file');
  late final _SslUseFileDart _sslCtxUsePrivateKeyFile =
      crypto.sslLibrary.lookupFunction<_SslUseFileNative, _SslUseFileDart>(
    'SSL_CTX_use_PrivateKey_file',
  );
  late final _SslCtxSetAlpnSelectCbDart _sslCtxSetAlpnSelectCb = crypto
      .sslLibrary
      .lookupFunction<_SslCtxSetAlpnSelectCbNative, _SslCtxSetAlpnSelectCbDart>(
          'SSL_CTX_set_alpn_select_cb');
  late final _ErrGetErrorDart _errGetError =
      crypto.cryptoLibrary.lookupFunction<_ErrGetErrorNative, _ErrGetErrorDart>(
    'ERR_get_error',
  );
  late final _ErrStringDart _errErrorStringN =
      crypto.cryptoLibrary.lookupFunction<_ErrStringNative, _ErrStringDart>(
    'ERR_error_string_n',
  );

  _BoringSslQuicServerSession createSession({
    required Uint8List originalDestinationConnectionId,
    required Uint8List initialSourceConnectionId,
    Uint8List? retrySourceConnectionId,
    int? preferredIpv4Port,
    bool enableEarlyData = true,
  }) {
    final ctx = _sslCtxNew(_tlsMethod());
    if (ctx == ffi.nullptr) throw _error('SSL_CTX_new failed');
    ffi.Pointer<ffi.Void> ssl = ffi.nullptr;
    final certPath = crypto.allocateCString(certificateFile);
    final keyPath = crypto.allocateCString(privateKeyFile);
    final ticketKeys = crypto.allocateBytes(
      Uint8List.fromList(List<int>.generate(48, (index) => index + 1)),
    );
    try {
      _check(
        _sslCtxSetTicketKeys(ctx, ticketKeys, 48),
        ffi.nullptr,
        'SSL_CTX_set_tlsext_ticket_keys',
      );
      _check(
        _sslCtxUseCertificateChainFile(ctx, certPath),
        ffi.nullptr,
        'SSL_CTX_use_certificate_chain_file',
      );
      _check(
        _sslCtxUsePrivateKeyFile(
          ctx,
          keyPath,
          _sslFiletypePem,
        ),
        ffi.nullptr,
        'SSL_CTX_use_PrivateKey_file',
      );
      _sslCtxSetAlpnSelectCb(
        ctx,
        ffi.Pointer.fromFunction<_AlpnSelectNative>(
            _selectAlpn, _sslTlsextErrAlertFatal),
        ffi.nullptr,
      );
      ssl = _sslNew(ctx);
      if (ssl == ffi.nullptr) throw _error('SSL_new failed');
      _sslSetAcceptState(ssl);
      _check(_sslSetMinProtoVersion(ssl, _tls13Version), ssl,
          'SSL_set_min_proto_version');
      _check(_sslSetMaxProtoVersion(ssl, _tls13Version), ssl,
          'SSL_set_max_proto_version');
      _check(_sslSetQuicMethod(ssl, _quicMethod), ssl, 'SSL_set_quic_method');
      _sslSetQuicUseLegacyCodepoint(ssl, 0);
      _sslSetEarlyDataEnabled(ssl, enableEarlyData ? 1 : 0);
      _setTransportParams(
        ssl,
        _serverTransportParameters(
          originalDestinationConnectionId: originalDestinationConnectionId,
          initialSourceConnectionId: initialSourceConnectionId,
          retrySourceConnectionId: retrySourceConnectionId,
          preferredIpv4Port: preferredIpv4Port,
          initialMaxData: initialMaxData,
          initialMaxStreamData: initialMaxStreamData,
          maxIdleTimeout: maxIdleTimeout,
        ),
      );
      final earlyDataContext = crypto.allocateBytes(
        Uint8List.fromList(
          utf8.encode(
            'h3;$initialMaxData;$initialMaxStreamData;$maxIdleTimeout',
          ),
        ),
      );
      try {
        _check(
          _sslSetQuicEarlyDataContext(
            ssl,
            earlyDataContext,
            'h3;$initialMaxData;$initialMaxStreamData;$maxIdleTimeout'.length,
          ),
          ssl,
          'SSL_set_quic_early_data_context',
        );
      } finally {
        crypto.free(earlyDataContext.cast<ffi.Void>());
      }
      final state = _BoringSslQuicServerState();
      _boringSslServerSessions[ssl.address] = state;
      return _BoringSslQuicServerSession(
        owner: this,
        context: ctx,
        ssl: ssl,
        state: state,
      );
    } catch (_) {
      if (ssl != ffi.nullptr) _sslFree(ssl);
      _sslCtxFree(ctx);
      rethrow;
    } finally {
      crypto.free(certPath.cast<ffi.Void>());
      crypto.free(keyPath.cast<ffi.Void>());
      crypto.free(ticketKeys.cast<ffi.Void>());
    }
  }

  int doHandshake(ffi.Pointer<ffi.Void> ssl) {
    final result = _sslDoHandshake(ssl);
    if (result == 1) return result;
    final error = _sslGetError(ssl, result);
    if (error == _sslErrorWantRead || error == _sslErrorWantWrite) {
      return result;
    }
    throw _sslError(ssl, result, 'SSL_do_handshake');
  }

  void provideQuicData(
    ffi.Pointer<ffi.Void> ssl,
    _QuicEncryptionLevel level,
    Uint8List data,
  ) {
    final bytes = crypto.allocateBytes(data);
    try {
      _check(
        _sslProvideQuicData(ssl, _toBoringSslLevel(level), bytes, data.length),
        ssl,
        'SSL_provide_quic_data',
      );
    } finally {
      crypto.free(bytes.cast<ffi.Void>());
    }
  }

  void dispose(ffi.Pointer<ffi.Void> ctx, ffi.Pointer<ffi.Void> ssl) {
    _boringSslServerSessions.remove(ssl.address);
    _sslFree(ssl);
    _sslCtxFree(ctx);
  }

  void _setTransportParams(ffi.Pointer<ffi.Void> ssl, Uint8List params) {
    final bytes = crypto.allocateBytes(params);
    try {
      _check(
        _sslSetQuicTransportParams(ssl, bytes, params.length),
        ssl,
        'SSL_set_quic_transport_params',
      );
    } finally {
      crypto.free(bytes.cast<ffi.Void>());
    }
  }

  void _check(int result, ffi.Pointer<ffi.Void> ssl, String operation) {
    if (result == 1) return;
    if (ssl == ffi.nullptr) throw _error(operation);
    throw _sslError(ssl, result, operation);
  }

  FormatException _sslError(
    ffi.Pointer<ffi.Void> ssl,
    int result,
    String operation,
  ) {
    final sslError = _sslGetError(ssl, result);
    final details = _lastErrorString();
    return FormatException(
      details == null
          ? '$operation failed with SSL_get_error=$sslError'
          : '$operation failed with SSL_get_error=$sslError: $details',
    );
  }

  FormatException _error(String operation) {
    final details = _lastErrorString();
    return FormatException(
      details == null ? '$operation failed' : '$operation failed: $details',
    );
  }

  String? _lastErrorString() {
    final code = _errGetError();
    if (code == 0) return null;
    final buffer = crypto.allocate(256);
    try {
      _errErrorStringN(code, buffer.cast<ffi.Uint8>(), 256);
      final bytes = buffer.cast<ffi.Uint8>().asTypedList(256);
      final end = bytes.indexOf(0);
      return utf8.decode(bytes.sublist(0, end < 0 ? bytes.length : end));
    } finally {
      crypto.free(buffer);
    }
  }

  static int _setReadSecret(
    ffi.Pointer<ffi.Void> ssl,
    int level,
    ffi.Pointer<ffi.Void> cipher,
    ffi.Pointer<ffi.Uint8> secret,
    int secretLen,
  ) {
    final state = _boringSslServerSessions[ssl.address];
    if (state == null) return 0;
    state.readSecrets[_fromBoringSslLevel(level)] = _BoringSslQuicSecret(
      level: _fromBoringSslLevel(level),
      cipher: cipher.address,
      secret: Uint8List.fromList(secret.asTypedList(secretLen)),
    );
    return 1;
  }

  static int _setWriteSecret(
    ffi.Pointer<ffi.Void> ssl,
    int level,
    ffi.Pointer<ffi.Void> cipher,
    ffi.Pointer<ffi.Uint8> secret,
    int secretLen,
  ) {
    final state = _boringSslServerSessions[ssl.address];
    if (state == null) return 0;
    state.writeSecrets[_fromBoringSslLevel(level)] = _BoringSslQuicSecret(
      level: _fromBoringSslLevel(level),
      cipher: cipher.address,
      secret: Uint8List.fromList(secret.asTypedList(secretLen)),
    );
    return 1;
  }

  static int _addHandshakeData(
    ffi.Pointer<ffi.Void> ssl,
    int level,
    ffi.Pointer<ffi.Uint8> data,
    int len,
  ) {
    final state = _boringSslServerSessions[ssl.address];
    if (state == null) return 0;
    state.pendingCrypto.add(
      _BoringSslQuicCryptoData(
        _fromBoringSslLevel(level),
        Uint8List.fromList(data.asTypedList(len)),
      ),
    );
    return 1;
  }

  static int _flushFlight(ffi.Pointer<ffi.Void> ssl) {
    final state = _boringSslServerSessions[ssl.address];
    if (state == null) return 0;
    state.flushCount++;
    return 1;
  }

  static int _sendAlert(ffi.Pointer<ffi.Void> ssl, int level, int alert) {
    final state = _boringSslServerSessions[ssl.address];
    if (state == null) return 0;
    state.lastAlert = alert;
    print('  server tls alert level=${_fromBoringSslLevel(level).name} '
        'alert=$alert');
    return 1;
  }

  static int _selectAlpn(
    ffi.Pointer<ffi.Void> ssl,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>> out,
    ffi.Pointer<ffi.Uint8> outLen,
    ffi.Pointer<ffi.Uint8> input,
    int inputLen,
    ffi.Pointer<ffi.Void> arg,
  ) {
    var offset = 0;
    while (offset < inputLen) {
      final length = (input + offset).value;
      offset++;
      if (offset + length > inputLen) break;
      final protocol = (input + offset).asTypedList(length);
      if (length == _h3Alpn.length && ascii.decode(protocol) == _h3Alpn) {
        out.value = input + offset;
        outLen.value = length;
        return _sslTlsextErrOk;
      }
      offset += length;
    }
    return _sslTlsextErrAlertFatal;
  }
}

class _BoringSslQuicServerSession {
  _BoringSslQuicServerSession({
    required this.owner,
    required this.context,
    required this.ssl,
    required this.state,
  });

  final _BoringSslQuicServer owner;
  final ffi.Pointer<ffi.Void> context;
  final ffi.Pointer<ffi.Void> ssl;
  final _BoringSslQuicServerState state;

  Map<_QuicEncryptionLevel, _BoringSslQuicSecret> get readSecrets =>
      state.readSecrets;

  Map<_QuicEncryptionLevel, _BoringSslQuicSecret> get writeSecrets =>
      state.writeSecrets;

  bool get handshakeComplete => owner._sslIsInitFinished(ssl) == 1;

  bool get earlyDataAccepted => owner._sslEarlyDataAccepted(ssl) == 1;

  void provideQuicData(_QuicEncryptionLevel level, Uint8List data) {
    owner.provideQuicData(ssl, level, data);
  }

  void driveHandshake() {
    for (var i = 0; i < 8; i++) {
      final before = state.pendingCrypto.length;
      owner.doHandshake(ssl);
      if (state.pendingCrypto.length == before) break;
    }
  }

  List<_BoringSslQuicCryptoData> takeCryptoData() {
    final out = List<_BoringSslQuicCryptoData>.of(state.pendingCrypto);
    state.pendingCrypto.clear();
    return out;
  }

  void close() => owner.dispose(context, ssl);
}

class _BoringSslQuicServerState {
  final readSecrets = <_QuicEncryptionLevel, _BoringSslQuicSecret>{};
  final writeSecrets = <_QuicEncryptionLevel, _BoringSslQuicSecret>{};
  final pendingCrypto = <_BoringSslQuicCryptoData>[];
  int flushCount = 0;
  int? lastAlert;
}

class _BoringSslQuicCryptoData {
  _BoringSslQuicCryptoData(this.level, this.data);

  final _QuicEncryptionLevel level;
  final Uint8List data;
}

class _BoringSslQuicSecret {
  _BoringSslQuicSecret({
    required this.level,
    required this.cipher,
    required this.secret,
  });

  final _QuicEncryptionLevel level;
  final int cipher;
  final Uint8List secret;
}

class _BoringSslCrypto {
  _BoringSslCrypto({
    required String sslLibraryPath,
    required String cryptoLibraryPath,
  })  : sslLibrary = ffi.DynamicLibrary.open(sslLibraryPath),
        cryptoLibrary = ffi.DynamicLibrary.open(cryptoLibraryPath) {
    _malloc = cryptoLibrary.lookupFunction<_MallocNative, _MallocDart>(
      'OPENSSL_malloc',
    );
    _free = cryptoLibrary.lookupFunction<_FreeNative, _FreeDart>(
      'OPENSSL_free',
    );
    _evpSha256 = cryptoLibrary.lookupFunction<_NoArgConstPointerNative,
        _NoArgConstPointerDart>('EVP_sha256');
    _evpSha384 = cryptoLibrary.lookupFunction<_NoArgConstPointerNative,
        _NoArgConstPointerDart>('EVP_sha384');
    _hkdfExtract = cryptoLibrary
        .lookupFunction<_HkdfExtractNative, _HkdfExtractDart>('HKDF_extract');
    _hkdfExpand = cryptoLibrary
        .lookupFunction<_HkdfExpandNative, _HkdfExpandDart>('HKDF_expand');
    _aeadAes128Gcm = cryptoLibrary.lookupFunction<_NoArgConstPointerNative,
        _NoArgConstPointerDart>('EVP_aead_aes_128_gcm');
    _aeadAes256Gcm = cryptoLibrary.lookupFunction<_NoArgConstPointerNative,
        _NoArgConstPointerDart>('EVP_aead_aes_256_gcm');
    _aeadCtxNew = cryptoLibrary
        .lookupFunction<_AeadCtxNewNative, _AeadCtxNewDart>('EVP_AEAD_CTX_new');
    _aeadCtxFree =
        cryptoLibrary.lookupFunction<_AeadCtxFreeNative, _AeadCtxFreeDart>(
            'EVP_AEAD_CTX_free');
    _aeadOpen = cryptoLibrary.lookupFunction<_AeadOpenNative, _AeadOpenDart>(
      'EVP_AEAD_CTX_open',
    );
    _aeadSeal = cryptoLibrary.lookupFunction<_AeadSealNative, _AeadSealDart>(
      'EVP_AEAD_CTX_seal',
    );
    _aesSetEncryptKey = cryptoLibrary.lookupFunction<_AesSetEncryptKeyNative,
        _AesSetEncryptKeyDart>('AES_set_encrypt_key');
    _aesEncrypt = cryptoLibrary
        .lookupFunction<_AesEncryptNative, _AesEncryptDart>('AES_encrypt');
    _sslCipherGetId =
        sslLibrary.lookupFunction<_SslCipherGetIdNative, _SslCipherGetIdDart>(
      'SSL_CIPHER_get_id',
    );
  }

  final ffi.DynamicLibrary sslLibrary;
  final ffi.DynamicLibrary cryptoLibrary;

  late final _MallocDart _malloc;
  late final _FreeDart _free;
  late final _NoArgConstPointerDart _evpSha256;
  late final _NoArgConstPointerDart _evpSha384;
  late final _HkdfExtractDart _hkdfExtract;
  late final _HkdfExpandDart _hkdfExpand;
  late final _NoArgConstPointerDart _aeadAes128Gcm;
  late final _NoArgConstPointerDart _aeadAes256Gcm;
  late final _AeadCtxNewDart _aeadCtxNew;
  late final _AeadCtxFreeDart _aeadCtxFree;
  late final _AeadOpenDart _aeadOpen;
  late final _AeadSealDart _aeadSeal;
  late final _AesSetEncryptKeyDart _aesSetEncryptKey;
  late final _AesEncryptDart _aesEncrypt;
  late final _SslCipherGetIdDart _sslCipherGetId;

  _QuicPacketKeys initialKeys(Uint8List dcid, {required bool client}) {
    final initialSecret = hkdfExtract(
      salt: Uint8List.fromList(_quicInitialSalt),
      ikm: dcid,
      length: 32,
    );
    final secret = hkdfExpandLabel(
      secret: initialSecret,
      label: client ? 'client in' : 'server in',
      length: 32,
    );
    return _QuicPacketKeys(
      key: hkdfExpandLabel(secret: secret, label: 'quic key', length: 16),
      iv: hkdfExpandLabel(secret: secret, label: 'quic iv', length: 12),
      hp: hkdfExpandLabel(secret: secret, label: 'quic hp', length: 16),
    );
  }

  _PacketProtection protectionForSecret(
    _BoringSslQuicSecret secret,
  ) {
    final cipherId = _sslCipherGetId(
      ffi.Pointer<ffi.Void>.fromAddress(secret.cipher),
    );
    final digest =
        cipherId == _tlsAes256GcmSha384 ? _evpSha384() : _evpSha256();
    final keyLength = cipherId == _tlsAes256GcmSha384 ? 32 : 16;
    return _PacketProtection(
      level: secret.level,
      keys: _QuicPacketKeys(
        key: hkdfExpandLabel(
          secret: secret.secret,
          label: 'quic key',
          length: keyLength,
          digest: digest,
        ),
        iv: hkdfExpandLabel(
          secret: secret.secret,
          label: 'quic iv',
          length: 12,
          digest: digest,
        ),
        hp: hkdfExpandLabel(
          secret: secret.secret,
          label: 'quic hp',
          length: keyLength,
          digest: digest,
        ),
      ),
      cipherId: cipherId,
    );
  }

  _PacketProtection nextProtectionForSecret(
    _BoringSslQuicSecret current,
  ) {
    final cipherId = _sslCipherGetId(
      ffi.Pointer<ffi.Void>.fromAddress(current.cipher),
    );
    final digest =
        cipherId == _tlsAes256GcmSha384 ? _evpSha384() : _evpSha256();
    final secretLength = cipherId == _tlsAes256GcmSha384 ? 48 : 32;
    final nextSecret = hkdfExpandLabel(
      secret: current.secret,
      label: 'quic ku',
      length: secretLength,
      digest: digest,
    );
    return protectionForSecret(_BoringSslQuicSecret(
      level: current.level,
      cipher: current.cipher,
      secret: nextSecret,
    ));
  }

  Uint8List hkdfExtract({
    required Uint8List salt,
    required Uint8List ikm,
    required int length,
  }) {
    final out = allocateBytes(Uint8List(length));
    final outLen = allocateIntPtr(length);
    final saltPtr = allocateBytes(salt);
    final ikmPtr = allocateBytes(ikm);
    try {
      final ok = _hkdfExtract(
        out,
        outLen,
        _evpSha256(),
        ikmPtr,
        ikm.length,
        saltPtr,
        salt.length,
      );
      if (ok != 1) throw const FormatException('HKDF_extract failed');
      return Uint8List.fromList(out.asTypedList(outLen.value));
    } finally {
      free(out.cast<ffi.Void>());
      free(outLen.cast<ffi.Void>());
      free(saltPtr.cast<ffi.Void>());
      free(ikmPtr.cast<ffi.Void>());
    }
  }

  Uint8List hkdfExpandLabel({
    required Uint8List secret,
    required String label,
    required int length,
    ffi.Pointer<ffi.Void>? digest,
  }) {
    final fullLabel = ascii.encode('tls13 $label');
    final info = BytesBuilder(copy: false)
      ..add([(length >> 8) & 0xff, length & 0xff])
      ..addByte(fullLabel.length)
      ..add(fullLabel)
      ..addByte(0);
    final out = allocateBytes(Uint8List(length));
    final secretPtr = allocateBytes(secret);
    final infoBytes = info.takeBytes();
    final infoPtr = allocateBytes(infoBytes);
    try {
      final ok = _hkdfExpand(
        out,
        length,
        digest ?? _evpSha256(),
        secretPtr,
        secret.length,
        infoPtr,
        infoBytes.length,
      );
      if (ok != 1) throw const FormatException('HKDF_expand failed');
      return Uint8List.fromList(out.asTypedList(length));
    } finally {
      free(out.cast<ffi.Void>());
      free(secretPtr.cast<ffi.Void>());
      free(infoPtr.cast<ffi.Void>());
    }
  }

  Uint8List seal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
    required int cipherId,
  }) {
    final outLen = allocateIntPtr(plaintext.length + _quicTagLength);
    final out = allocateBytes(Uint8List(plaintext.length + _quicTagLength));
    final keyPtr = allocateBytes(key);
    final noncePtr = allocateBytes(nonce);
    final inputPtr = allocateBytes(plaintext);
    final aadPtr = allocateBytes(aad);
    final ctx = _aeadCtxNew(
      cipherId == _tlsAes256GcmSha384 ? _aeadAes256Gcm() : _aeadAes128Gcm(),
      keyPtr,
      key.length,
      0,
    );
    try {
      if (ctx == ffi.nullptr) throw const FormatException('AEAD init failed');
      final ok = _aeadSeal(
        ctx,
        out,
        outLen,
        plaintext.length + _quicTagLength,
        noncePtr,
        nonce.length,
        inputPtr,
        plaintext.length,
        aadPtr,
        aad.length,
      );
      if (ok != 1) throw const FormatException('AEAD seal failed');
      return Uint8List.fromList(out.asTypedList(outLen.value));
    } finally {
      if (ctx != ffi.nullptr) _aeadCtxFree(ctx);
      free(outLen.cast<ffi.Void>());
      free(out.cast<ffi.Void>());
      free(keyPtr.cast<ffi.Void>());
      free(noncePtr.cast<ffi.Void>());
      free(inputPtr.cast<ffi.Void>());
      free(aadPtr.cast<ffi.Void>());
    }
  }

  Uint8List? open({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List aad,
    required int cipherId,
  }) {
    if (cipherId != _tlsAes128GcmSha256 &&
        cipherId != _tlsAes256GcmSha384) {
      throw UnsupportedError('Unsupported QUIC packet cipher $cipherId');
    }
    final outLen = allocateIntPtr(ciphertext.length);
    final out = allocateBytes(Uint8List(ciphertext.length));
    final keyPtr = allocateBytes(key);
    final noncePtr = allocateBytes(nonce);
    final inputPtr = allocateBytes(ciphertext);
    final aadPtr = allocateBytes(aad);
    final ctx = _aeadCtxNew(
      cipherId == _tlsAes256GcmSha384 ? _aeadAes256Gcm() : _aeadAes128Gcm(),
      keyPtr,
      key.length,
      0,
    );
    try {
      if (ctx == ffi.nullptr) throw const FormatException('AEAD init failed');
      final ok = _aeadOpen(
        ctx,
        out,
        outLen,
        ciphertext.length,
        noncePtr,
        nonce.length,
        inputPtr,
        ciphertext.length,
        aadPtr,
        aad.length,
      );
      if (ok != 1) return null;
      return Uint8List.fromList(out.asTypedList(outLen.value));
    } finally {
      if (ctx != ffi.nullptr) _aeadCtxFree(ctx);
      free(outLen.cast<ffi.Void>());
      free(out.cast<ffi.Void>());
      free(keyPtr.cast<ffi.Void>());
      free(noncePtr.cast<ffi.Void>());
      free(inputPtr.cast<ffi.Void>());
      free(aadPtr.cast<ffi.Void>());
    }
  }

  Uint8List aesMask(Uint8List hpKey, Uint8List sample) {
    final keyPtr = allocateBytes(hpKey);
    final samplePtr = allocateBytes(sample);
    final out = allocateBytes(Uint8List(16));
    final aesKey = allocate(256);
    try {
      if (_aesSetEncryptKey(keyPtr, hpKey.length * 8, aesKey) != 0) {
        throw const FormatException('AES_set_encrypt_key failed');
      }
      _aesEncrypt(samplePtr, out, aesKey);
      return Uint8List.fromList(out.asTypedList(16));
    } finally {
      free(keyPtr.cast<ffi.Void>());
      free(samplePtr.cast<ffi.Void>());
      free(out.cast<ffi.Void>());
      free(aesKey);
    }
  }

  ffi.Pointer<ffi.Uint8> allocateBytes(Uint8List bytes) {
    final pointer = allocate(bytes.length).cast<ffi.Uint8>();
    pointer.asTypedList(bytes.length).setAll(0, bytes);
    return pointer;
  }

  ffi.Pointer<ffi.Uint8> allocateCString(String value) {
    return allocateBytes(Uint8List.fromList([...utf8.encode(value), 0]));
  }

  ffi.Pointer<ffi.IntPtr> allocateIntPtr(int value) {
    final pointer = allocate(ffi.sizeOf<ffi.IntPtr>()).cast<ffi.IntPtr>();
    pointer.value = value;
    return pointer;
  }

  ffi.Pointer<ffi.Void> allocate(int size) {
    final pointer = _malloc(size, ffi.nullptr, 0);
    if (pointer == ffi.nullptr) {
      throw OutOfMemoryError();
    }
    return pointer;
  }

  void free(ffi.Pointer<ffi.Void> pointer) {
    _free(pointer, ffi.nullptr, 0);
  }
}
