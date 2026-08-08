part of '../http3_adapter.dart';

class QpackErrorCode {
  static const int decompressionFailed = 0x0200;
  static const int encoderStreamError = 0x0201;
  static const int decoderStreamError = 0x0202;
}

class QpackException implements Exception {
  const QpackException(this.errorCode, this.message);

  final int errorCode;
  final String message;

  @override
  String toString() => 'QPACK error 0x${errorCode.toRadixString(16)}: $message';
}

/// Connection-scoped QPACK decoder.
///
/// Encoder-stream instructions can arrive independently of field sections.
/// [decodeHeaders] therefore completes asynchronously when a field section is
/// blocked waiting for the required dynamic-table insertions.
class QpackDecoder {
  QpackDecoder({
    required this.maximumTableCapacity,
    required this.maximumBlockedStreams,
    this.onDecoderInstructions,
  }) : _table = _QpackDynamicTable(maximumTableCapacity);

  final int maximumTableCapacity;
  final int maximumBlockedStreams;
  final void Function(Uint8List instructions)? onDecoderInstructions;
  final _QpackDynamicTable _table;
  final _encoderStreamBuffer = <int>[];
  final _blocked = <_QpackBlockedFieldSection>[];

  int get insertCount => _table.insertCount;

  Future<Map<String, String>> decodeHeaders(
    int streamId,
    List<int> headerBlock,
  ) {
    try {
      final bytes = Uint8List.fromList(headerBlock);
      final prefix = _decodeFieldSectionPrefix(bytes);
      if (prefix.requiredInsertCount <= _table.insertCount) {
        return Future<Map<String, String>>.value(
          _decodeFieldSection(streamId, bytes, prefix),
        );
      }

      final blockedStreams = _blocked.map((item) => item.streamId).toSet();
      if (!blockedStreams.contains(streamId) &&
          blockedStreams.length >= maximumBlockedStreams) {
        throw const QpackException(
          QpackErrorCode.decompressionFailed,
          'Peer exceeded SETTINGS_QPACK_BLOCKED_STREAMS',
        );
      }
      final completer = Completer<Map<String, String>>();
      _blocked.add(_QpackBlockedFieldSection(
        streamId: streamId,
        bytes: bytes,
        prefix: prefix,
        completer: completer,
      ));
      return completer.future;
    } on QpackException catch (error, stackTrace) {
      return Future<Map<String, String>>.error(error, stackTrace);
    } on Object catch (error) {
      return Future<Map<String, String>>.error(
        QpackException(QpackErrorCode.decompressionFailed, '$error'),
      );
    }
  }

  void addEncoderStreamData(List<int> data) {
    _encoderStreamBuffer.addAll(data);
    var inserted = 0;
    try {
      while (_encoderStreamBuffer.isNotEmpty) {
        final instruction =
            _tryParseQpackEncoderInstruction(_encoderStreamBuffer);
        if (instruction == null) break;
        _encoderStreamBuffer.removeRange(0, instruction.length);
        if (instruction is _QpackSetCapacityInstruction) {
          _table.setCapacity(instruction.capacity);
        } else if (instruction is _QpackInsertNameReferenceInstruction) {
          final name = instruction.isStatic
              ? _qpackStaticEntry(instruction.nameIndex).name
              : _table.entryByEncoderRelativeIndex(instruction.nameIndex).name;
          _table.insert(name, instruction.value);
          inserted++;
        } else if (instruction is _QpackInsertLiteralInstruction) {
          _table.insert(instruction.name, instruction.value);
          inserted++;
        } else if (instruction is _QpackDuplicateInstruction) {
          final entry =
              _table.entryByEncoderRelativeIndex(instruction.relativeIndex);
          _table.insert(entry.name, entry.value);
          inserted++;
        }
      }
    } on QpackException {
      rethrow;
    } on Object catch (error) {
      throw QpackException(QpackErrorCode.encoderStreamError, '$error');
    }

    if (inserted != 0) {
      final writer = _QuicWriter();
      _writeQpackPrefixedInteger(writer, inserted, 6, 0x00);
      onDecoderInstructions?.call(writer.takeBytes());
      _resumeBlockedFieldSections();
    }
  }

  void cancelStream(int streamId) {
    var removed = false;
    _blocked.removeWhere((section) {
      if (section.streamId != streamId) return false;
      removed = true;
      if (!section.completer.isCompleted) {
        section.completer.completeError(
          StateError('QPACK field section on stream $streamId was cancelled'),
        );
      }
      return true;
    });
    if (removed) {
      final writer = _QuicWriter();
      _writeQpackPrefixedInteger(writer, streamId, 6, 0x40);
      onDecoderInstructions?.call(writer.takeBytes());
    }
  }

  void failBlocked(Object error, [StackTrace? stackTrace]) {
    for (final section in _blocked) {
      if (!section.completer.isCompleted) {
        section.completer.completeError(error, stackTrace);
      }
    }
    _blocked.clear();
  }

  void _resumeBlockedFieldSections() {
    final ready = _blocked
        .where(
          (section) => section.prefix.requiredInsertCount <= _table.insertCount,
        )
        .toList();
    _blocked.removeWhere(ready.contains);
    for (final section in ready) {
      try {
        section.completer.complete(
          _decodeFieldSection(
            section.streamId,
            section.bytes,
            section.prefix,
          ),
        );
      } on Object catch (error, stackTrace) {
        section.completer.completeError(error, stackTrace);
      }
    }
  }

  _QpackFieldSectionPrefix _decodeFieldSectionPrefix(Uint8List bytes) {
    final encodedInsertCount = _readQpackPrefixedInteger(bytes, 0, 8);
    final deltaOffset = encodedInsertCount.length;
    if (deltaOffset >= bytes.length) {
      throw const QpackException(
        QpackErrorCode.decompressionFailed,
        'Truncated field section prefix',
      );
    }
    final deltaBase = _readQpackPrefixedInteger(bytes, deltaOffset, 7);
    final requiredInsertCount =
        _decodeRequiredInsertCount(encodedInsertCount.value);
    final sign = bytes[deltaOffset] & 0x80 != 0;
    if (sign && requiredInsertCount <= deltaBase.value) {
      throw const QpackException(
        QpackErrorCode.decompressionFailed,
        'Field section Base would be negative',
      );
    }
    final base = sign
        ? requiredInsertCount - deltaBase.value - 1
        : requiredInsertCount + deltaBase.value;
    return _QpackFieldSectionPrefix(
      requiredInsertCount: requiredInsertCount,
      base: base,
      length: encodedInsertCount.length + deltaBase.length,
    );
  }

  int _decodeRequiredInsertCount(int encodedInsertCount) {
    if (encodedInsertCount == 0) return 0;
    final maxEntries = maximumTableCapacity ~/ 32;
    final fullRange = 2 * maxEntries;
    if (maxEntries == 0 || encodedInsertCount > fullRange) {
      throw const QpackException(
        QpackErrorCode.decompressionFailed,
        'Invalid Required Insert Count',
      );
    }
    final maxValue = _table.insertCount + maxEntries;
    final maxWrapped = (maxValue ~/ fullRange) * fullRange;
    var requiredInsertCount = maxWrapped + encodedInsertCount - 1;
    if (requiredInsertCount > maxValue) {
      if (requiredInsertCount <= fullRange) {
        throw const QpackException(
          QpackErrorCode.decompressionFailed,
          'Invalid wrapped Required Insert Count',
        );
      }
      requiredInsertCount -= fullRange;
    }
    if (requiredInsertCount == 0) {
      throw const QpackException(
        QpackErrorCode.decompressionFailed,
        'Required Insert Count zero was not encoded as zero',
      );
    }
    return requiredInsertCount;
  }

  Map<String, String> _decodeFieldSection(
    int streamId,
    Uint8List bytes,
    _QpackFieldSectionPrefix prefix,
  ) {
    try {
      final reader = _QuicReader(bytes)..offset = prefix.length;
      final headers = <String, String>{};
      var largestReference = -1;

      _QpackDynamicEntry dynamicEntry(int absoluteIndex) {
        if (absoluteIndex < 0 || absoluteIndex >= prefix.requiredInsertCount) {
          throw FormatException(
            'Invalid dynamic table reference $absoluteIndex',
          );
        }
        largestReference = max(largestReference, absoluteIndex);
        return _table.entryByAbsoluteIndex(absoluteIndex);
      }

      while (!reader.isDone) {
        final first = reader.readByte();
        if (first & 0x80 != 0) {
          final index = _readQpackPrefixedIntegerFromReader(reader, first, 6);
          if (first & 0x40 != 0) {
            final entry = _qpackStaticEntry(index);
            headers[entry.name] = entry.value;
          } else {
            final entry = dynamicEntry(prefix.base - index - 1);
            headers[entry.name] = entry.value;
          }
          continue;
        }
        if (first & 0xf0 == 0x10) {
          final index = _readQpackPrefixedIntegerFromReader(reader, first, 4);
          final entry = dynamicEntry(prefix.base + index);
          headers[entry.name] = entry.value;
          continue;
        }
        if (first & 0xc0 == 0x40) {
          final index = _readQpackPrefixedIntegerFromReader(reader, first, 4);
          final name = first & 0x10 != 0
              ? _qpackStaticEntry(index).name
              : dynamicEntry(prefix.base - index - 1).name;
          headers[name] = _readQpackStringFromReader(reader, 7);
          continue;
        }
        if (first & 0xf0 == 0x00) {
          final index = _readQpackPrefixedIntegerFromReader(reader, first, 3);
          final name = dynamicEntry(prefix.base + index).name;
          headers[name] = _readQpackStringFromReader(reader, 7);
          continue;
        }
        if (first & 0xe0 == 0x20) {
          final huffman = first & 0x08 != 0;
          final nameLength =
              _readQpackPrefixedIntegerFromReader(reader, first, 3);
          final encodedName = reader.readBytes(nameLength);
          final name = ascii.decode(
            huffman ? huffmanDecode(encodedName) : encodedName,
          );
          headers[name] = _readQpackStringFromReader(reader, 7);
          continue;
        }
        throw FormatException(
          'Unsupported field representation 0x${first.toRadixString(16)}',
        );
      }

      final expectedRequiredInsertCount = largestReference + 1;
      if (prefix.requiredInsertCount != expectedRequiredInsertCount) {
        throw FormatException(
          'Required Insert Count ${prefix.requiredInsertCount} does not match '
          'largest reference $expectedRequiredInsertCount',
        );
      }
      if (prefix.requiredInsertCount != 0) {
        final writer = _QuicWriter();
        _writeQpackPrefixedInteger(writer, streamId, 7, 0x80);
        onDecoderInstructions?.call(writer.takeBytes());
      }
      return headers;
    } on QpackException {
      rethrow;
    } on Object catch (error) {
      throw QpackException(QpackErrorCode.decompressionFailed, '$error');
    }
  }
}

/// Connection-scoped QPACK encoder for request field sections.
class QpackEncoder {
  QpackEncoder({
    this.preferredTableCapacity = 4096,
    this.onEncoderInstructions,
  }) : _table = _QpackDynamicTable(0);

  final int preferredTableCapacity;
  final void Function(Uint8List instructions)? onEncoderInstructions;
  final _QpackDynamicTable _table;
  final _decoderStreamBuffer = <int>[];
  final _outstandingSections = <int, Queue<_QpackOutstandingSection>>{};
  final _referenceCounts = <int, int>{};

  int _knownReceivedCount = 0;
  int _maximumBlockedStreams = 0;
  bool _configured = false;

  int get insertCount => _table.insertCount;
  int get knownReceivedCount => _knownReceivedCount;

  void configure({
    required int maximumTableCapacity,
    required int maximumBlockedStreams,
  }) {
    if (_configured) return;
    _configured = true;
    _maximumBlockedStreams = maximumBlockedStreams;
    final capacity = min(preferredTableCapacity, maximumTableCapacity);
    _table
      ..maximumCapacity = maximumTableCapacity
      ..setCapacity(capacity);
    if (capacity != 0) {
      final writer = _QuicWriter();
      _writeQpackPrefixedInteger(writer, capacity, 5, 0x20);
      onEncoderInstructions?.call(writer.takeBytes());
    }
  }

  Uint8List encodeHeaders(int streamId, Map<String, String> headers) {
    final representations = <_QpackFieldRepresentation>[];
    final encoderInstructions = _QuicWriter();
    final referenced = <int>{};
    final canRiskBlocking = _blockedStreamCount < _maximumBlockedStreams;

    headers.forEach((originalName, value) {
      final name = originalName.toLowerCase();
      final staticExact = _qpackFindStaticEntry(name, value);
      if (staticExact != null) {
        representations.add(_QpackStaticIndexedRepresentation(staticExact));
        return;
      }

      final sensitive = _qpackSensitiveFieldNames.contains(name);
      var dynamicExact = sensitive ? null : _table.find(name, value);
      if (dynamicExact == null &&
          !sensitive &&
          _shouldInsert(name, value) &&
          _canInsert(name, value)) {
        _writeInsertInstruction(encoderInstructions, name, value);
        dynamicExact = _table.insert(name, value);
      }

      if (dynamicExact != null &&
          (dynamicExact.absoluteIndex < _knownReceivedCount ||
              canRiskBlocking)) {
        referenced.add(dynamicExact.absoluteIndex);
        representations.add(
          _QpackDynamicIndexedRepresentation(dynamicExact.absoluteIndex),
        );
        return;
      }

      final staticName = _qpackFindStaticName(name);
      if (staticName != null) {
        representations.add(_QpackLiteralNameReferenceRepresentation(
          index: staticName,
          isStatic: true,
          value: value,
          neverIndexed: sensitive,
        ));
        return;
      }
      final dynamicName = sensitive ? null : _table.findName(name);
      if (dynamicName != null &&
          dynamicName.absoluteIndex < _knownReceivedCount) {
        referenced.add(dynamicName.absoluteIndex);
        representations.add(_QpackLiteralNameReferenceRepresentation(
          index: dynamicName.absoluteIndex,
          isStatic: false,
          value: value,
          neverIndexed: false,
        ));
        return;
      }
      representations.add(_QpackLiteralRepresentation(
        name,
        value,
        neverIndexed: sensitive,
      ));
    });

    final requiredInsertCount =
        referenced.isEmpty ? 0 : referenced.reduce(max) + 1;
    final base = requiredInsertCount == 0 ? 0 : _table.insertCount;
    final writer = _QuicWriter();
    _writeQpackPrefixedInteger(
      writer,
      _encodeRequiredInsertCount(requiredInsertCount),
      8,
      0x00,
    );
    if (base >= requiredInsertCount) {
      _writeQpackPrefixedInteger(
        writer,
        base - requiredInsertCount,
        7,
        0x00,
      );
    } else {
      _writeQpackPrefixedInteger(
        writer,
        requiredInsertCount - base - 1,
        7,
        0x80,
      );
    }
    for (final representation in representations) {
      representation.write(writer, base);
    }

    final instructions = encoderInstructions.takeBytes();
    if (instructions.isNotEmpty) {
      onEncoderInstructions?.call(instructions);
    }
    if (requiredInsertCount != 0) {
      final section = _QpackOutstandingSection(
        requiredInsertCount,
        referenced,
      );
      (_outstandingSections[streamId] ??= Queue()).add(section);
      for (final index in referenced) {
        _referenceCounts[index] = (_referenceCounts[index] ?? 0) + 1;
      }
    }
    return writer.takeBytes();
  }

  void addDecoderStreamData(List<int> data) {
    _decoderStreamBuffer.addAll(data);
    try {
      while (_decoderStreamBuffer.isNotEmpty) {
        final instruction =
            _tryParseQpackDecoderInstruction(_decoderStreamBuffer);
        if (instruction == null) break;
        _decoderStreamBuffer.removeRange(0, instruction.length);
        if (instruction is _QpackSectionAcknowledgmentInstruction) {
          _acknowledgeSection(instruction.streamId);
        } else if (instruction is _QpackStreamCancellationInstruction) {
          _cancelStream(instruction.streamId);
        } else if (instruction is _QpackInsertCountIncrementInstruction) {
          if (instruction.increment == 0 ||
              _knownReceivedCount + instruction.increment >
                  _table.insertCount) {
            throw const QpackException(
              QpackErrorCode.decoderStreamError,
              'Invalid Insert Count Increment',
            );
          }
          _knownReceivedCount += instruction.increment;
        }
      }
    } on QpackException {
      rethrow;
    } on Object catch (error) {
      throw QpackException(QpackErrorCode.decoderStreamError, '$error');
    }
  }

  void cancelStream(int streamId) => _cancelStream(streamId);

  int get _blockedStreamCount {
    var count = 0;
    for (final sections in _outstandingSections.values) {
      if (sections.any(
        (section) => section.requiredInsertCount > _knownReceivedCount,
      )) {
        count++;
      }
    }
    return count;
  }

  int _encodeRequiredInsertCount(int requiredInsertCount) {
    if (requiredInsertCount == 0) return 0;
    final maxEntries = _table.maximumCapacity ~/ 32;
    if (maxEntries == 0) {
      throw StateError('Cannot encode a dynamic reference at zero capacity');
    }
    return (requiredInsertCount % (2 * maxEntries)) + 1;
  }

  bool _shouldInsert(String name, String value) {
    if (name.startsWith(':')) return false;
    return utf8.encode(name).length + utf8.encode(value).length + 32 <=
        _table.capacity;
  }

  bool _canInsert(String name, String value) {
    return _table.canInsert(name, value, (entry) {
      return entry.absoluteIndex < _knownReceivedCount &&
          (_referenceCounts[entry.absoluteIndex] ?? 0) == 0;
    });
  }

  void _writeInsertInstruction(
    _QuicWriter writer,
    String name,
    String value,
  ) {
    final staticName = _qpackFindStaticName(name);
    if (staticName != null) {
      _writeQpackPrefixedInteger(writer, staticName, 6, 0xc0);
    } else {
      final dynamicName = _table.findName(name);
      if (dynamicName != null) {
        final relative = _table.insertCount - dynamicName.absoluteIndex - 1;
        _writeQpackPrefixedInteger(writer, relative, 6, 0x80);
      } else {
        _writeQpackString(writer, name, 5, 0x40);
      }
    }
    _writeQpackString(writer, value, 7, 0x00);
  }

  void _acknowledgeSection(int streamId) {
    final sections = _outstandingSections[streamId];
    if (sections == null || sections.isEmpty) {
      throw QpackException(
        QpackErrorCode.decoderStreamError,
        'Section Acknowledgment for stream $streamId has no pending section',
      );
    }
    final section = sections.removeFirst();
    _knownReceivedCount = max(_knownReceivedCount, section.requiredInsertCount);
    _releaseReferences(section);
    if (sections.isEmpty) _outstandingSections.remove(streamId);
  }

  void _cancelStream(int streamId) {
    final sections = _outstandingSections.remove(streamId);
    if (sections == null) return;
    for (final section in sections) {
      _releaseReferences(section);
    }
  }

  void _releaseReferences(_QpackOutstandingSection section) {
    for (final index in section.references) {
      final remaining = (_referenceCounts[index] ?? 1) - 1;
      if (remaining == 0) {
        _referenceCounts.remove(index);
      } else {
        _referenceCounts[index] = remaining;
      }
    }
  }
}

const _qpackSensitiveFieldNames = <String>{
  'authorization',
  'cookie',
  'proxy-authorization',
  'set-cookie',
};

class _QpackDynamicTable {
  _QpackDynamicTable(this.maximumCapacity);

  int maximumCapacity;
  int capacity = 0;
  int insertCount = 0;
  int _size = 0;
  final _entries = <_QpackDynamicEntry>[];

  void setCapacity(int value) {
    if (value < 0 || value > maximumCapacity) {
      throw QpackException(
        QpackErrorCode.encoderStreamError,
        'Dynamic table capacity $value exceeds maximum $maximumCapacity',
      );
    }
    capacity = value;
    while (_size > capacity && _entries.isNotEmpty) {
      _evictOldest();
    }
  }

  bool canInsert(
    String name,
    String value,
    bool Function(_QpackDynamicEntry entry) canEvict,
  ) {
    final entrySize = _QpackDynamicEntry.sizeOf(name, value);
    if (entrySize > capacity) return false;
    var available = capacity - _size;
    for (final entry in _entries) {
      if (available >= entrySize) return true;
      if (!canEvict(entry)) return false;
      available += entry.size;
    }
    return available >= entrySize;
  }

  _QpackDynamicEntry insert(String name, String value) {
    final entrySize = _QpackDynamicEntry.sizeOf(name, value);
    if (entrySize > capacity) {
      throw QpackException(
        QpackErrorCode.encoderStreamError,
        'Dynamic table entry is larger than its capacity',
      );
    }
    while (_size + entrySize > capacity && _entries.isNotEmpty) {
      _evictOldest();
    }
    final entry = _QpackDynamicEntry(
      absoluteIndex: insertCount++,
      name: name,
      value: value,
    );
    _entries.add(entry);
    _size += entry.size;
    return entry;
  }

  _QpackDynamicEntry entryByAbsoluteIndex(int absoluteIndex) {
    return _entries.firstWhere(
      (entry) => entry.absoluteIndex == absoluteIndex,
      orElse: () => throw FormatException(
        'Dynamic table entry $absoluteIndex was evicted or not inserted',
      ),
    );
  }

  _QpackDynamicEntry entryByEncoderRelativeIndex(int relativeIndex) {
    return entryByAbsoluteIndex(insertCount - relativeIndex - 1);
  }

  _QpackDynamicEntry? find(String name, String value) {
    for (var i = _entries.length - 1; i >= 0; i--) {
      final entry = _entries[i];
      if (entry.name == name && entry.value == value) return entry;
    }
    return null;
  }

  _QpackDynamicEntry? findName(String name) {
    for (var i = _entries.length - 1; i >= 0; i--) {
      final entry = _entries[i];
      if (entry.name == name) return entry;
    }
    return null;
  }

  void _evictOldest() {
    final entry = _entries.removeAt(0);
    _size -= entry.size;
  }
}

class _QpackDynamicEntry {
  _QpackDynamicEntry({
    required this.absoluteIndex,
    required this.name,
    required this.value,
  }) : size = sizeOf(name, value);

  final int absoluteIndex;
  final String name;
  final String value;
  final int size;

  static int sizeOf(String name, String value) =>
      utf8.encode(name).length + utf8.encode(value).length + 32;
}

class _QpackFieldSectionPrefix {
  const _QpackFieldSectionPrefix({
    required this.requiredInsertCount,
    required this.base,
    required this.length,
  });

  final int requiredInsertCount;
  final int base;
  final int length;
}

class _QpackBlockedFieldSection {
  const _QpackBlockedFieldSection({
    required this.streamId,
    required this.bytes,
    required this.prefix,
    required this.completer,
  });

  final int streamId;
  final Uint8List bytes;
  final _QpackFieldSectionPrefix prefix;
  final Completer<Map<String, String>> completer;
}

class _QpackOutstandingSection {
  const _QpackOutstandingSection(this.requiredInsertCount, this.references);

  final int requiredInsertCount;
  final Set<int> references;
}

abstract class _QpackFieldRepresentation {
  void write(_QuicWriter writer, int base);
}

class _QpackStaticIndexedRepresentation implements _QpackFieldRepresentation {
  const _QpackStaticIndexedRepresentation(this.index);

  final int index;

  @override
  void write(_QuicWriter writer, int base) {
    _writeQpackPrefixedInteger(writer, index, 6, 0xc0);
  }
}

class _QpackDynamicIndexedRepresentation implements _QpackFieldRepresentation {
  const _QpackDynamicIndexedRepresentation(this.absoluteIndex);

  final int absoluteIndex;

  @override
  void write(_QuicWriter writer, int base) {
    if (absoluteIndex < base) {
      _writeQpackPrefixedInteger(
        writer,
        base - absoluteIndex - 1,
        6,
        0x80,
      );
    } else {
      _writeQpackPrefixedInteger(
        writer,
        absoluteIndex - base,
        4,
        0x10,
      );
    }
  }
}

class _QpackLiteralNameReferenceRepresentation
    implements _QpackFieldRepresentation {
  const _QpackLiteralNameReferenceRepresentation({
    required this.index,
    required this.isStatic,
    required this.value,
    required this.neverIndexed,
  });

  final int index;
  final bool isStatic;
  final String value;
  final bool neverIndexed;

  @override
  void write(_QuicWriter writer, int base) {
    if (isStatic) {
      _writeQpackPrefixedInteger(
        writer,
        index,
        4,
        0x40 | (neverIndexed ? 0x20 : 0) | 0x10,
      );
    } else if (index < base) {
      _writeQpackPrefixedInteger(
        writer,
        base - index - 1,
        4,
        0x40 | (neverIndexed ? 0x20 : 0),
      );
    } else {
      _writeQpackPrefixedInteger(
        writer,
        index - base,
        3,
        neverIndexed ? 0x08 : 0x00,
      );
    }
    _writeQpackString(writer, value, 7, 0x00);
  }
}

class _QpackLiteralRepresentation implements _QpackFieldRepresentation {
  const _QpackLiteralRepresentation(
    this.name,
    this.value, {
    required this.neverIndexed,
  });

  final String name;
  final String value;
  final bool neverIndexed;

  @override
  void write(_QuicWriter writer, int base) {
    _writeQpackString(
      writer,
      name,
      3,
      0x20 | (neverIndexed ? 0x10 : 0),
    );
    _writeQpackString(writer, value, 7, 0x00);
  }
}

abstract class _QpackInstruction {
  const _QpackInstruction(this.length);

  final int length;
}

class _QpackSetCapacityInstruction extends _QpackInstruction {
  const _QpackSetCapacityInstruction(super.length, this.capacity);

  final int capacity;
}

class _QpackInsertNameReferenceInstruction extends _QpackInstruction {
  const _QpackInsertNameReferenceInstruction(
    super.length, {
    required this.isStatic,
    required this.nameIndex,
    required this.value,
  });

  final bool isStatic;
  final int nameIndex;
  final String value;
}

class _QpackInsertLiteralInstruction extends _QpackInstruction {
  const _QpackInsertLiteralInstruction(
    super.length,
    this.name,
    this.value,
  );

  final String name;
  final String value;
}

class _QpackDuplicateInstruction extends _QpackInstruction {
  const _QpackDuplicateInstruction(super.length, this.relativeIndex);

  final int relativeIndex;
}

class _QpackSectionAcknowledgmentInstruction extends _QpackInstruction {
  const _QpackSectionAcknowledgmentInstruction(super.length, this.streamId);

  final int streamId;
}

class _QpackStreamCancellationInstruction extends _QpackInstruction {
  const _QpackStreamCancellationInstruction(super.length, this.streamId);

  final int streamId;
}

class _QpackInsertCountIncrementInstruction extends _QpackInstruction {
  const _QpackInsertCountIncrementInstruction(super.length, this.increment);

  final int increment;
}

_QpackInstruction? _tryParseQpackEncoderInstruction(List<int> bytes) {
  if (bytes.isEmpty) return null;
  final first = bytes.first;
  if (first & 0x80 != 0) {
    final nameIndex = _tryReadQpackPrefixedInteger(bytes, 0, 6);
    if (nameIndex == null) return null;
    final value = _tryReadQpackString(bytes, nameIndex.length, 7);
    if (value == null) return null;
    return _QpackInsertNameReferenceInstruction(
      nameIndex.length + value.length,
      isStatic: first & 0x40 != 0,
      nameIndex: nameIndex.value,
      value: value.value,
    );
  }
  if (first & 0xc0 == 0x40) {
    final name = _tryReadQpackString(bytes, 0, 5);
    if (name == null) return null;
    final value = _tryReadQpackString(bytes, name.length, 7);
    if (value == null) return null;
    return _QpackInsertLiteralInstruction(
      name.length + value.length,
      name.value,
      value.value,
    );
  }
  if (first & 0xe0 == 0x20) {
    final capacity = _tryReadQpackPrefixedInteger(bytes, 0, 5);
    if (capacity == null) return null;
    return _QpackSetCapacityInstruction(capacity.length, capacity.value);
  }
  final index = _tryReadQpackPrefixedInteger(bytes, 0, 5);
  if (index == null) return null;
  return _QpackDuplicateInstruction(index.length, index.value);
}

_QpackInstruction? _tryParseQpackDecoderInstruction(List<int> bytes) {
  if (bytes.isEmpty) return null;
  final first = bytes.first;
  if (first & 0x80 != 0) {
    final streamId = _tryReadQpackPrefixedInteger(bytes, 0, 7);
    if (streamId == null) return null;
    return _QpackSectionAcknowledgmentInstruction(
      streamId.length,
      streamId.value,
    );
  }
  if (first & 0xc0 == 0x40) {
    final streamId = _tryReadQpackPrefixedInteger(bytes, 0, 6);
    if (streamId == null) return null;
    return _QpackStreamCancellationInstruction(
      streamId.length,
      streamId.value,
    );
  }
  final increment = _tryReadQpackPrefixedInteger(bytes, 0, 6);
  if (increment == null) return null;
  return _QpackInsertCountIncrementInstruction(
    increment.length,
    increment.value,
  );
}

class _QpackInteger {
  const _QpackInteger(this.value, this.length);

  final int value;
  final int length;
}

class _QpackString {
  const _QpackString(this.value, this.length);

  final String value;
  final int length;
}

_QpackInteger? _tryReadQpackPrefixedInteger(
  List<int> bytes,
  int offset,
  int prefixBits,
) {
  if (offset >= bytes.length) return null;
  final maxPrefix = (1 << prefixBits) - 1;
  var value = bytes[offset] & maxPrefix;
  if (value < maxPrefix) return _QpackInteger(value, 1);
  var shift = 0;
  var cursor = offset + 1;
  while (true) {
    if (cursor >= bytes.length) return null;
    final next = bytes[cursor++];
    if (shift >= 63 || (next & 0x7f) > (0x3fffffffffffffff - value) >> shift) {
      throw const FormatException('QPACK integer exceeds 62 bits');
    }
    value += (next & 0x7f) << shift;
    if (next & 0x80 == 0) {
      return _QpackInteger(value, cursor - offset);
    }
    shift += 7;
  }
}

_QpackInteger _readQpackPrefixedInteger(
  List<int> bytes,
  int offset,
  int prefixBits,
) {
  return _tryReadQpackPrefixedInteger(bytes, offset, prefixBits) ??
      (throw const FormatException('Truncated QPACK integer'));
}

int _readQpackPrefixedIntegerFromReader(
  _QuicReader reader,
  int first,
  int prefixBits,
) {
  final maxPrefix = (1 << prefixBits) - 1;
  var value = first & maxPrefix;
  if (value < maxPrefix) return value;
  var shift = 0;
  while (true) {
    final next = reader.readByte();
    if (shift >= 63 || (next & 0x7f) > (0x3fffffffffffffff - value) >> shift) {
      throw const FormatException('QPACK integer exceeds 62 bits');
    }
    value += (next & 0x7f) << shift;
    if (next & 0x80 == 0) return value;
    shift += 7;
  }
}

_QpackString? _tryReadQpackString(
  List<int> bytes,
  int offset,
  int prefixBits,
) {
  final length = _tryReadQpackPrefixedInteger(bytes, offset, prefixBits);
  if (length == null) return null;
  final end = offset + length.length + length.value;
  if (end > bytes.length) return null;
  final encoded = Uint8List.fromList(
    bytes.sublist(offset + length.length, end),
  );
  final huffman = bytes[offset] & (1 << prefixBits) != 0;
  final decoded = huffman ? huffmanDecode(encoded) : encoded;
  return _QpackString(utf8.decode(decoded), end - offset);
}

String _readQpackStringFromReader(_QuicReader reader, int prefixBits) {
  final first = reader.readByte();
  final huffman = first & (1 << prefixBits) != 0;
  final length = _readQpackPrefixedIntegerFromReader(reader, first, prefixBits);
  final encoded = reader.readBytes(length);
  return utf8.decode(huffman ? huffmanDecode(encoded) : encoded);
}

void _writeQpackPrefixedInteger(
  _QuicWriter writer,
  int value,
  int prefixBits,
  int firstByteMask,
) {
  if (value < 0 || value > 0x3fffffffffffffff) {
    throw RangeError.range(value, 0, 0x3fffffffffffffff, 'value');
  }
  final maxPrefix = (1 << prefixBits) - 1;
  if (value < maxPrefix) {
    writer.writeByte(firstByteMask | value);
    return;
  }
  writer.writeByte(firstByteMask | maxPrefix);
  var remaining = value - maxPrefix;
  while (remaining >= 128) {
    writer.writeByte((remaining & 0x7f) | 0x80);
    remaining >>= 7;
  }
  writer.writeByte(remaining);
}

void _writeQpackString(
  _QuicWriter writer,
  String value,
  int prefixBits,
  int firstByteMask,
) {
  final bytes = utf8.encode(value);
  _writeQpackPrefixedInteger(
    writer,
    bytes.length,
    prefixBits,
    firstByteMask,
  );
  writer.writeBytes(bytes);
}

_QpackStaticEntry _qpackStaticEntry(int index) {
  if (index < 0 || index >= _qpackStaticTable.length) {
    throw FormatException('Invalid QPACK static table index $index');
  }
  return _qpackStaticTable[index];
}

int? _qpackFindStaticEntry(String name, String value) {
  for (var i = 0; i < _qpackStaticTable.length; i++) {
    final entry = _qpackStaticTable[i];
    if (entry.name == name && entry.value == value) return i;
  }
  return null;
}

int? _qpackFindStaticName(String name) {
  for (var i = 0; i < _qpackStaticTable.length; i++) {
    if (_qpackStaticTable[i].name == name) return i;
  }
  return null;
}
