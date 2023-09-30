import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'multipart_file.dart';
import 'options.dart';
import 'utils.dart';

/// A class to create readable "multipart/form-data" streams.
/// It can be used to submit forms and file uploads to http server.
class FormData {
  static const String _BOUNDARY_PRE_TAG = '----WebKitFormBoundary';
  static const _BOUNDARY_LENGTH = _BOUNDARY_PRE_TAG.length + 16;
  static const _kAlphaNumericEncodingMap = [
      0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
      0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
      0x57, 0x58, 0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
      0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
      0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x30, 0x31, 0x32,
      0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42];

  late String _boundary;

  /// The boundary of FormData, it consists of a constant prefix and a random
  /// postfix to assure the the boundary unpredictable and unique, each FormData
  /// instance will be different.
  String get boundary => _boundary;

  final _newlineRegExp = RegExp(r'\r\n|\r|\n');

  /// The form fields to send for this request.
  final fields = <MapEntry<String, String>>[];

  /// The [files].
  final files = <MapEntry<String, MultipartFile>>[];

  /// Whether [finalize] has been called.
  bool get isFinalized => _isFinalized;
  bool _isFinalized = false;

  FormData() {
    _init();
  }

  /// Create FormData instance with a Map.
  FormData.fromMap(
    Map<String, dynamic> map, [
    ListFormat collectionFormat = ListFormat.multi,
  ]) {
    _init();
    encodeMap(
      map,
      (key, value) {
        if (value == null) return null;
        if (value is MultipartFile) {
          files.add(MapEntry(key, value));
        } else {
          fields.add(MapEntry(key, value.toString()));
        }
        return null;
      },
      listFormat: collectionFormat,
      encode: false,
    );
  }

  void _init() {
    // Assure the boundary unpredictable and unique
    var random = Random();
    _boundary = _BOUNDARY_PRE_TAG +
        String.fromCharCodes(Iterable.generate(16, (i) => _kAlphaNumericEncodingMap[random.nextInt(64)]));
  }

  /// Returns the header string for a field. The return value is guaranteed to
  /// contain only ASCII characters.
  String _headerForField(String name, String value) {
    var header =
        'content-disposition: form-data; name="${_browserEncode(name)}"';
    if (!isPlainAscii(value)) {
      header = '$header\r\n'
          'content-type: text/plain; charset=utf-8\r\n'
          'content-transfer-encoding: binary';
    }
    return '$header\r\n\r\n';
  }

  /// Returns the header string for a file. The return value is guaranteed to
  /// contain only ASCII characters.
  String _headerForFile(MapEntry<String, MultipartFile> entry) {
    var file = entry.value;
    var header =
        'content-disposition: form-data; name="${_browserEncode(entry.key)}"';
    if (file.filename != null) {
      header = '$header; filename="${_browserEncode(file.filename)}"';
    }
    header = '$header\r\n'
        'content-type: ${file.contentType}';
    if (file.headers != null) {
      // append additional headers
      file.headers!.forEach((key, values) {
        values.forEach((value) {
          header = '$header\r\n'
              '$key: $value';
        });
      });
    }
    return '$header\r\n\r\n';
  }

  /// Encode [value] in the same way browsers do.
  String? _browserEncode(String? value) {
    // http://tools.ietf.org/html/rfc2388 mandates some complex encodings for
    // field names and file names, but in practice user agents seem not to
    // follow this at all. Instead, they URL-encode `\r`, `\n`, and `\r\n` as
    // `\r\n`; URL-encode `"`; and do nothing else (even for `%` or non-ASCII
    // characters). We follow their behavior.
    if (value == null) {
      return null;
    }
    return value.replaceAll(_newlineRegExp, '%0D%0A').replaceAll('"', '%22');
  }

  /// The total length of the request body, in bytes. This is calculated from
  /// [fields] and [files] and cannot be set manually.
  int get length {
    var length = 0;
    fields.forEach((entry) {
      length += '--'.length +
          _BOUNDARY_LENGTH +
          '\r\n'.length +
          utf8.encode(_headerForField(entry.key, entry.value)).length +
          utf8.encode(entry.value).length +
          '\r\n'.length;
    });

    for (var file in files) {
      length += '--'.length +
          _BOUNDARY_LENGTH +
          '\r\n'.length +
          utf8.encode(_headerForFile(file)).length +
          file.value.length +
          '\r\n'.length;
    }

    return length + '--'.length + _BOUNDARY_LENGTH + '--\r\n'.length;
  }

  Stream<List<int>> finalize() {
    if (isFinalized) {
      throw StateError("Can't finalize a finalized MultipartFile.");
    }
    _isFinalized = true;
    var controller = StreamController<List<int>>(sync: false);
    void writeAscii(String string) {
      controller.add(utf8.encode(string));
    }

    void writeUtf8(String string) => controller.add(utf8.encode(string));
    void writeLine() => controller.add([13, 10]); // \r\n

    fields.forEach((entry) {
      writeAscii('--$boundary\r\n');
      writeAscii(_headerForField(entry.key, entry.value));
      writeUtf8(entry.value);
      writeLine();
    });

    Future.forEach<MapEntry<String, MultipartFile>>(files, (file) {
      writeAscii('--$boundary\r\n');
      writeAscii(_headerForFile(file));
      return writeStreamToSink(file.value.finalize(), controller)
          .then((_) => writeLine());
    }).then((_) {
      writeAscii('--$boundary--\r\n');
      controller.close();
    });
    return controller.stream;
  }

  ///Transform the entire FormData contents as a list of bytes asynchronously.
  Future<List<int>> readAsBytes() {
    return Future(() => finalize().reduce((a, b) => [...a, ...b]));
  }
}
