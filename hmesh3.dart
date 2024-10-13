import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:html/parser.dart';
import 'package:http/http.dart';

import 'dart:math';

final verbose = true;

void setup() {
  HttpOverrides.global = MyHttpOverrides();
}

void main(List<String> args) async {
  setup();
  var parser = ArgParser();

  parser.addOption('username', abbr: 'u', help: 'Username (typically "admin" by default)');
  parser.addOption('password', abbr: 'p', help: 'Password (typically the wifi password)');
  parser.addMultiOption('ips', abbr: 'i', help: 'List of IP addresses of the routers', splitCommas: true);
  parser.addFlag('reboot', abbr: 'r', negatable: false, help: 'Reboot the routers');
  parser.addFlag('wan-detect', abbr: 'w', negatable: false, help: 'Print WAN detect output');
  parser.addFlag('device-info', abbr: 'd', negatable: false, help: 'Print Device Info');
  parser.addFlag('help', abbr: 'h', negatable: false, help: 'Display this help message');

  var argResults = parser.parse(args);

  // Help
  if (argResults['help'] as bool) {
    print('A Command-line utility for communicating with Huawei Mesh 3 API');
    print('Usage: dart run hmesh3.dart [options]');
    print('');
    print('Example: dart run hmesh3.dart -u "username" -p "password" -i "192.168.9.103","192.168.9.106" --reboot');
    print('');
    print(parser.usage);
    return;
  }

  final String username = argResults['username'] ?? '';
  final String password = argResults['password'] ?? '';
  final List<String> ips = argResults['ips'];
  final bool reboot = argResults['reboot'];
  final bool wanDetect = argResults['wan-detect'];
  final bool deviceInfo = argResults['device-info'];

  final bool hasUsernameAndPassword = username.isNotEmpty && password.isNotEmpty;

  if (!hasUsernameAndPassword && reboot) {
    print('cannot reboot without both username and password');
  }

  if (ips.isEmpty) {
    print('please provide at least one ip address');
  }

  if (!wanDetect && !reboot) {
    print('please select an option "reboot" or "wan detect"');
  }

  for (var ip in ips) {
    if (!isValidIp(ip)) {
      print('The given IP ($ip) is not a valid IP address');
      exit(1);
    }
  }

  final conns = <RouterConnection>[];
  for (var ip in ips) {
    conns.add(RouterConnection(ip: ip, username: username, password: password));
  }

  for (var conn in conns) {
    print('connecting to router ${conn.ip}');
    try {
      print('-- signing in');
      if (reboot) {
        await conn.start();
        await conn.signin();
        print('-- rebooting');
        await conn.reboot();
      }
      if (wanDetect) {
        await conn.wandetect();
      }
      if (deviceInfo) {
        // await conn.wandetect();
        await conn.deviceInfo();
      }
    } catch (e) {
      print('something went wrong $e');
    } finally {
      print('closing connection to router ${conn.ip}');
      conn.dispose();
      print('--------------------------------');
    }
  }
}

class RouterConnection {
  final String ip;
  final String username;
  final String password;
  late final client = Client();

  RouterConnection({required this.username, required this.password, required this.ip}) {}

  // These values need to be updated after each successful request.
  String? csrfToken;
  String? csrfParam;
  String? cookies;

  // TODO: it would be better if we create our own post/get and intercept them
  //       but note that not all responses' bodies may contain a JSON (especially error response)
  //       that would contain CSRF token/param
  void updateCSRFsAndCookies({required Map<String, String> headers, required Map<String, dynamic> body}) {
    if (body.containsKey('csrf_param')) {
      csrfParam = body['csrf_param'];
    }
    if (body.containsKey('csrf_token')) {
      csrfToken = body['csrf_token'];
    }

    if (headers.containsKey('set-cookie')) {
      cookies = headers['set-cookie'].toString().split(';').first;
    }
  }

  Future<void> start() async {
    final response = await client.get(
      Uri.parse(APIs.home(ip)),
      headers: generateHeaders(ip, cookies: cookies, get: true),
    );

    if (response.statusCode != 200) {
      return Future.error('could not request homepage');
    }

    final html = parse(response.body);

    csrfToken = html.querySelector("meta[name='csrf_token']")?.attributes['content'];
    csrfParam = html.querySelector("meta[name='csrf_param']")?.attributes['content'];

    if (csrfToken == null || csrfParam == null) {
      return Future.error('could not obtain CSRF token ($csrfToken) or CSRF param ($csrfParam)');
    }

    if (response.headers.containsKey('set-cookie')) {
      cookies = response.headers['set-cookie'].toString().split(';').first;
    }
  }

  // Signing-in takes two steps:
  // - sending the username and a client nonce | receive server nonce and salt
  // - sending a proof using a salted password
  Future<void> signin() async {
    final clientNonce = getRandomHex(64); // 32 bytes

    final payload = {
      "csrf": {"csrf_param": csrfParam, "csrf_token": csrfToken},
      "data": {
        "username": username,
        "firstnonce": clientNonce,
      },
    };
    final payloadJSON = json.encode(payload);

    final loginResponse = await client.post(
      Uri.parse(APIs.login(ip)),
      headers: generateHeaders(ip, cookies: cookies, contentLength: utf8.encode((payloadJSON)).length),
      body: payloadJSON,
    );

    final body = json.decode(loginResponse.body) as Map<String, dynamic>;

    updateCSRFsAndCookies(headers: loginResponse.headers, body: body);

    if (body['err'] != 0) {
      return Future.error(body);
    }

    await proofLogIn(clientNonce, body);
  }

  Future<void> proofLogIn(String clientNonce, Map<String, dynamic> initialLoginResponse) async {
    final salt = initialLoginResponse['salt'] as String;
    final servernonce = initialLoginResponse['servernonce'] as String;
    final iterations = initialLoginResponse['iterations'] as int;

    final authMsg = clientNonce + "," + servernonce + "," + servernonce;

    final clientSecret = await generateClientKey(password, salt, iterations);
    final clientProof = await generateClientProof(clientSecret, authMsg);

    final loginPostData = {
      "csrf": {"csrf_param": csrfParam, "csrf_token": csrfToken},
      "data": {"finalnonce": servernonce, "clientproof": hex.encode(clientProof)},
    };

    final loginProofResponse = await client.post(
      Uri.parse(APIs.loginProof(ip)),
      headers: generateHeaders(ip, cookies: cookies),
      body: utf8.encode(json.encode(loginPostData)),
    );

    final proofBody = json.decode(loginProofResponse.body) as Map<String, dynamic>;
    updateCSRFsAndCookies(headers: loginProofResponse.headers, body: proofBody);

    if (proofBody['err'] != 0) {
      return Future.error('Log in proof failed: $proofBody');
    }
  }

  Future<void> wandetect() async {
    final res = await client.get(
      Uri.parse(APIs.wandetect(ip)),
    );

    if (res.statusCode != 200) {
      print('WAN detect failed');
    } else {
      final body = json.decode(res.body) as Map<String, dynamic>;
      print('');
      print('WAN DETECT OUTPUT FOR $ip:');
      body.forEach((key, value) {
        print('   $key : $value');
      });
      print('');
      updateCSRFsAndCookies(headers: res.headers, body: body);
    }
  }

  Future<void> deviceInfo() async {
    final url = Uri.parse(APIs.deviceInfo(ip));
    final res = await client.get(url);

    if (res.statusCode != 200) {
      print('WAN detect failed');
    } else {
      final body = json.decode(res.body) as Map<String, dynamic>;
      print('');
      print('WAN DETECT OUTPUT FOR $ip:');
      body.forEach((key, value) {
        print('   $key : $value');
      });
      print('');
      updateCSRFsAndCookies(headers: res.headers, body: body);
    }
  }

  Future<void> reboot() async {
    final payload = {
      "csrf": {"csrf_param": csrfParam, "csrf_token": csrfToken},
    };

    final payloadJSON = json.encode(payload);

    final rebootResponse = await client.post(
      Uri.parse(APIs.reboot(ip)),
      headers: generateHeaders(ip, cookies: cookies, contentLength: utf8.encode(payloadJSON).length),
      body: payloadJSON,
    );

    if (rebootResponse.statusCode != 200) {
      return Future.error(
          'Could not reboot the router ($ip) -- status code ${rebootResponse.statusCode}: ${rebootResponse.body}');
    } else {
      print('rebooted ${rebootResponse.body}');
    }

    updateCSRFsAndCookies(headers: rebootResponse.headers, body: json.decode(rebootResponse.body));
  }

  void dispose() async {
    client.close();
  }
}

/* -------------------------------------------------------------------------- */
/*                                 HTTP / API                                 */
/* -------------------------------------------------------------------------- */

class APIs {
  static String login(String ip) => "https://$ip/api/system/user_login_nonce";

  static String loginProof(String ip) => "https://$ip/api/system/user_login_proof";

  /* -------------------------------------------------------------------------- */
  /*                          Does not require Log In:                          */
  /* -------------------------------------------------------------------------- */
  static String home(String ip) => 'https://$ip/html/index.html';

  static String wandetect(String ip) => 'https://$ip/api/ntwk/wandetect';

  static String deviceInfo(String ip) => 'https://$ip/api/system/deviceinfo';

  /* -------------------------------------------------------------------------- */
  /*                               Requires Log In                              */
  /* -------------------------------------------------------------------------- */
  static String reboot(String ip) => "https://$ip/api/service/reboot.cgi";
}

Map<String, String> generateHeaders(String ip, {String? cookies, int? contentLength, bool get = false}) {
  if (get) {
    return {
      "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
      'Accept-Encoding': 'gzip, deflate',
      'Accept': '*/*',
      'Connection': 'keep-alive',
      if (cookies != null) "Cookie": cookies,
    };
  }
  return {
    "Connection": "keep-alive",
    "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
    "Accept-Encoding": "gzip, deflate",
    "Cache-Control": "max-age=0",
    "Origin": "https://$ip",
    "Content-Type": "application/json;charset=UTF-8",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "X-Requested-With": "XMLHttpRequest",
    "_ResponseFormat": "JSON",
    "Referer": "https://$ip/html/index.html",
    "Accept-Language": "en-US,en;q=0.9,ar;q=0.8,es;q=0.7,pt;q=0.6",
    if (cookies != null) "Cookie": cookies,
    if (contentLength != null) "Content-Length": contentLength.toString(),
  };
}

class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}

/* -------------------------------------------------------------------------- */
/*                                   CRYPTO                                   */
/* -------------------------------------------------------------------------- */

Future<List<int>> generateClientKey(String password, String salt, int iterations) async {
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: iterations,
    bits: 256,
  );

  final secretKey = await pbkdf2.deriveKeyFromPassword(
    password: password,
    nonce: hex.decode(salt),
  );

  return await secretKey.extractBytes();
}

// credit: https://github.com/quzard/HW-TC7102/blob/main/hw.py
Future<List<int>> generateClientProof(List<int> clientSecret, String authMsg) async {
  final clientMac = await Hmac(Sha256()).calculateMac(
    clientSecret,
    secretKey: SecretKey(utf8.encode('Client Key')), // I think it can be any key
  );

  final clientMacHash = await Sha256().hash(clientMac.bytes);

  final clientSignature = await Hmac(Sha256()).calculateMac(
    clientMacHash.bytes,
    secretKey: SecretKey(utf8.encode(authMsg)),
  );

  final clientProof = Uint8List(clientMac.bytes.length);
  for (var i = 0; i < clientMac.bytes.length; i++) {
    clientProof[i] = clientMac.bytes[i] ^ clientSignature.bytes[i];
  }

  return clientProof;
}

/* -------------------------------------------------------------------------- */
/*                                    UTIL                                    */
/* -------------------------------------------------------------------------- */

String getRandomHex(int length) {
  final chars = '0123456789abcdef';
  final generator = Random();
  return String.fromCharCodes(Iterable.generate(length, (_) => chars.codeUnitAt(generator.nextInt(chars.length))));
}

void l(String string, [bool error = false]) {
  if (verbose || error) {
    print(string);
  }
}

bool isValidIp(String ip) {
  return InternetAddress.tryParse(ip) != null;
}
