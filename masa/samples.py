"""Builds deliberately vulnerable Android/iOS sample fixtures for the demo.

No Android SDK or Xcode is required: every binary format is produced with
the same pure-Python writers the analyzer parses (masa.axml, masa.plist),
plus minimal hand-rolled dex / ELF / Mach-O builders.

Outputs under <outdir>/:
  VulnerableBank.apk            - Android fixture
  VulnerableBank.ipa            - iOS fixture
  VulnerableBank-Android/       - plain source-tree fixture (apktool-like)
  reports/                      - analysis reports (written by `masa demo`)
"""

import os
import struct
import zipfile

from . import axml, plist

# =====================================================================
# Android vulnerable app source
# =====================================================================

MAIN_JAVA = '''package com.vulnbank.demo;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {

    // --- M1: hardcoded credentials ------------------------------------
    private static final String API_KEY = "AIzaSyDfB5VulnerableKeyDemo1234567890ABCDEF";
    private static final String STRIPE_SECRET = "sk_live_51HrQp0VulnerableStripeSecret";
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String FIREBASE_URL = "https://vulnbank-7f3a2.firebaseio.com";
    private static final String AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2dWxuYmFuayIsInJvbGUiOiJhZG1pbiJ9.s0meS1gnatureValu3ForTheDemoOnly";
    private static final String DB_PASSWORD = "SuperSecret1!";

    // --- M10: broken cryptography -------------------------------------
    private static final String ENC_KEY = "ThisIsASecretKey";
    private static final String iv = "1234567890123456";

    private byte[] encrypt(String plain) throws Exception {
        // DES is deprecated; ECB leaks structure; hardcoded key+IV
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(ENC_KEY.getBytes("UTF-8"), "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv.getBytes("UTF-8")));
        return cipher.doFinal(plain.getBytes("UTF-8"));
    }

    private String weakHash(String input) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        return bytesToHex(md.digest(input.getBytes("UTF-8")));
    }

    private String xorEncrypt(byte[] data, byte[] key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ key[i % key.length]);   // custom "crypto"
        }
        return bytesToHex(out);
    }

    // --- M9: insecure storage -----------------------------------------
    private void cacheToken(String token) {
        getSharedPreferences("vulnbank_prefs", Context.MODE_PRIVATE).edit().putString("auth_token", token).commit();   // plaintext token in prefs
        getApplicationContext().openFileOutput("session.dat", MODE_WORLD_READABLE);
    }

    private void saveToExternal(String payload) {
        android.os.Environment.getExternalStorageDirectory();   // world-readable dirs
    }

    private void openDb(String user, String pin) {
        SQLiteDatabase db = openOrCreateDatabase("vulnbank.db", MODE_PRIVATE, null);
        db.rawQuery("SELECT * FROM accounts WHERE user=" + user + " AND pin=" + pin, null);
    }

    // --- M5: insecure communication ------------------------------------
    private void trustAllCerts() {
        javax.net.ssl.TrustManager[] trustAll = new javax.net.ssl.TrustManager[] {
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
                public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }
            }
        };
    }

    private void skipHostnameCheck() {
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
            new javax.net.ssl.HostnameVerifier() {
                public boolean verify(String host, javax.net.ssl.SSLSession s) { return true; }
            });
    }

    private void fetchBalance() {
        // cleartext HTTP endpoint + token in URL
        String url = "http://api.insecure-bank.com/v1/balance?access_token=" + AUTH_TOKEN;
        // staging endpoint shipped in release build
        String staging = "https://api.vulnbank.staging.internal/v1/ping";
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d("VulnBank", "login token: " + AUTH_TOKEN);      // M6: credential in logs
        Log.d("VulnBank", "password is " + DB_PASSWORD);

        WebView web = new WebView(this);
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setAllowFileAccess(true);
        web.getSettings().setAllowUniversalAccessFromFileURLs(true);
        web.addJavascriptInterface(new JsBridge(), "androidBridge");   // M4: JS bridge
        web.loadUrl("http://m.insecure-bank.com/home");

        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        Log.d("VulnBank", "imei=" + tm.getDeviceId());        // M6: hardware ID

        int rnd = new java.util.Random(1337).nextInt();       // seeded PRNG

        String[] endpoints = new String[] { "http://192.168.1.20:8080/api" }; // hardcoded IP

        // M3: client-side authorization
        if (isAdmin()) { startActivity(new android.content.Intent(this, AdminActivity.class)); }
    }

    private boolean isAdmin() { return true; }   // client-side admin check

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public class JsBridge {
        @JavascriptInterface
        public String getBalance() { return "0"; }
    }
}
'''

# =====================================================================
# dex writer (fixture): minimal classes.dex with a string table
# =====================================================================

def _uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def make_dex(strings):
    """Build a minimal dex file carrying the given strings."""
    body = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(body))
        body += _uleb(len(s.encode("utf-16-le")) // 2)
        body += s.encode("utf-8")
        body.append(0)
    while len(body) % 4:
        body.append(0)
    n = len(strings)
    ids_size = 0x70 + 4 * n
    h = bytearray(0x70)
    h[0:8] = b"dex\n035\x00"
    h[32:36] = (ids_size + len(body)).to_bytes(4, "little")
    h[36:40] = (0x70).to_bytes(4, "little")
    h[40:44] = (0x12345678).to_bytes(4, "little")
    h[56:60] = n.to_bytes(4, "little")
    h[60:64] = (0x70).to_bytes(4, "little")
    h[104:108] = len(body).to_bytes(4, "little")
    h[108:112] = ids_size.to_bytes(4, "little")
    ids = b"".join(struct.pack("<I", ids_size + o) for o in offsets)
    return bytes(h) + ids + bytes(body)


DEX_STRINGS = [
    "com.vulnbank.demo", "MainActivity", "Lcom/vulnbank/demo/MainActivity;",
    "API_KEY", "AIzaSyDfB5VulnerableKeyDemo1234567890ABCDEF",
    "STRIPE_SECRET", "sk_live_51HrQp0VulnerableStripeSecret",
    "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE",
    "AUTH_TOKEN", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2dWxuYmFuayIsInJvbGUiOiJhZG1pbiJ9.s0meS1gnatureValu3ForTheDemoOnly",
    "DB_PASSWORD", "SuperSecret1!",
    "DES/ECB/PKCS5Padding", "MD5", "ThisIsASecretKey", "1234567890123456",
    "vulnbank_prefs", "auth_token", "session.dat", "vulnbank.db",
    "http://api.insecure-bank.com/v1/balance?access_token=eyJhbGciOiJIUzI1NiJ9",
    "https://api.vulnbank.staging.internal/v1/ping",
    "http://192.168.1.20:8080/api",
    "getSharedPreferences", "openOrCreateDatabase", "rawQuery",
    "rawQuery(\"SELECT * FROM accounts WHERE user=\" + user + \" AND pin=\" + pin, null)",
    "addJavascriptInterface", "setAllowFileAccess",
    "android.permission.READ_SMS", "android.permission.CAMERA",
    "org.apache.http.impl.client.DefaultHttpClient",
    "DexClassLoader",
]

# =====================================================================
# ELF64 writer (fixture): non-RELRO, executable-stack native library
# =====================================================================

def make_elf64(data):
    """Minimal ELF64 shared object (PIE) with two program headers."""
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8,
        3, 0xB7, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    ph = bytearray()
    ph += struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, len(data), len(data),
                      0x1000)                 # PT_LOAD (R-X)
    ph += struct.pack("<IIQQQQQQ", 0x6474e551, 7, 0, 0, 0, 0, 0, 0x10)
    return ehdr + bytes(ph) + data            # PT_GNU_STACK (RWX, no RELRO)


NATIVE_DATA = (
    b"\x00\x00\x80\x52" * 16 +                       # fake instructions
    b"\x00\x00\x00\x00" +
    b"strcpy(dst, src);\x00sprintf(buf, fmt, arg);\x00" +
    b"system(\"/system/bin/sh\");\x00" +
    b"rand();\x00" +
    b"MD5_Init(&ctx);\x00DES_key_schedule\x00" +
    b"hardcoded_native_secret = \"AKIAIOSFODNN7EXAMPLE\"\x00" +
    b"libvulnbank.so v1.0 (native crypto helper)\x00"
)

# =====================================================================
# iOS vulnerable app
# =====================================================================

INFO_PLIST = {
    "CFBundleIdentifier": "com.vulnbank.demo",
    "CFBundleName": "VulnBank",
    "CFBundleDisplayName": "VulnBank",
    "CFBundleExecutable": "VulnBank",
    "CFBundleShortVersionString": "1.0",
    "CFBundleVersion": "1",
    "MinimumOSVersion": "10.0",
    "CFBundleSupportedPlatforms": ["iPhoneOS"],
    "UIRequiredDeviceCapabilities": ["arm64"],
    "UIBackgroundModes": ["location"],
    "NSAppTransportSecurity": {
        "NSAllowsArbitraryLoads": True,
        "NSExceptionDomains": {
            "api.insecure-bank.com": {
                "NSExceptionAllowsInsecureHTTPLoads": True,
                "NSIncludesSubdomains": True,
            },
        },
    },
}


def make_macho64(payload):
    """Minimal Mach-O 64 (arm64) executable with LC_ENCRYPTION_INFO_64."""
    seg = struct.pack(
        "<II16sQQQQIIII", 0x19, 0x48,
        b"__TEXT\x00" + b"\x00" * 9,
        0x100000000, len(payload), 0, len(payload),
        7, 5, 0, 0)
    enc = struct.pack("<IIIIII", 0x2C, 0x18, 0, 0, 0, 0)   # cryptid = 0
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2,
                         2, len(seg) + len(enc), 0, 0)
    return header + seg + enc + payload


MACHO_PAYLOAD = (
    b"\x00\x00\x00\x00" * 8 +
    b"NSUserDefaults setObject:forKey:password\x00" +
    b"http://api.insecure-bank.com/v1/balance?access_token=eyJhbGciOiJIUzI1NiJ9\x00" +
    b'auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2dWxuYmFuayJ9.fakesig00000000"\x00' +
    b"sk_live_51HrQp0VulnerableStripeSecret\x00" +
    b"AKIAIOSFODNN7EXAMPLE\x00" +
    b"SecTrustEvaluateWithError\x00" +
    b"verify(result, err) { return true; }\x00" +
    b"getDeviceId\x00" +
    b"ASIdentifierManager\x00" +
    b"strcpy(dst, src);\x00" +
    b"VulnBank.app/VulnBank\x00" +
    b"MD5\x00"
)

PROVISIONING_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>AppIDName</key><string>VulnBank</string>
  <key>CreationDate</key><date>2026-01-01T00:00:00Z</date>
  <key>ExpirationDate</key><date>2027-01-01T00:00:00Z</date>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key><string>TEAM12345.com.vulnbank.demo</string>
    <key>com.apple.developer.team-identifier</key><string>TEAM12345</string>
    <key>get-task-allow</key><true/>
    <key>aps-environment</key><string>development</string>
  </dict>
</dict></plist>
"""

# =====================================================================
# builders
# =====================================================================

def _attr(name, value, dtype=axml.TYPE_STRING):
    return axml.Attribute(axml.ANDROID_NS, name, dtype,
                          value if dtype == axml.TYPE_INT_DEC else None,
                          value)


def build_android_manifest():
    m = axml.Element(None, "manifest")
    m.attrs = [_attr("package", "com.vulnbank.demo"),
               _attr("versionCode", 1, axml.TYPE_INT_DEC),
               _attr("versionName", "1.0")]
    sdk = axml.Element(None, "uses-sdk")
    sdk.attrs = [_attr("minSdkVersion", 21, axml.TYPE_INT_DEC),
                 _attr("targetSdkVersion", 26, axml.TYPE_INT_DEC)]
    m.children.append(sdk)
    for perm in ("android.permission.INTERNET",
                 "android.permission.CAMERA",
                 "android.permission.RECORD_AUDIO",
                 "android.permission.ACCESS_FINE_LOCATION",
                 "android.permission.READ_SMS",
                 "android.permission.READ_CONTACTS",
                 "android.permission.SYSTEM_ALERT_WINDOW",
                 "android.permission.QUERY_ALL_PACKAGES"):
        p = axml.Element(None, "uses-permission")
        p.attrs = [_attr("name", perm)]
        m.children.append(p)
    app = axml.Element(None, "application")
    app.attrs = [_attr("label", "VulnBank"),
                 _attr("debuggable", True, axml.TYPE_BOOLEAN),
                 _attr("allowBackup", True, axml.TYPE_BOOLEAN),
                 _attr("usesCleartextTraffic", True, axml.TYPE_BOOLEAN),
                 _attr("networkSecurityConfig", "@xml/network_security_config")]
    act_main = axml.Element(None, "activity")
    act_main.attrs = [_attr("name", ".MainActivity"),
                      _attr("exported", True, axml.TYPE_BOOLEAN)]
    filt = axml.Element(None, "intent-filter")
    a1 = axml.Element(None, "action")
    a1.attrs = [_attr("name", "android.intent.action.MAIN")]
    c1 = axml.Element(None, "category")
    c1.attrs = [_attr("name", "android.intent.category.LAUNCHER")]
    filt.children = [a1, c1]
    act_main.children = [filt]
    app.children.append(act_main)
    act_open = axml.Element(None, "activity")
    act_open.attrs = [_attr("name", ".OpenAccountActivity"),
                      _attr("exported", True, axml.TYPE_BOOLEAN)]
    app.children.append(act_open)
    recv = axml.Element(None, "receiver")
    recv.attrs = [_attr("name", ".SmsReceiver"),
                  _attr("exported", True, axml.TYPE_BOOLEAN)]
    filt2 = axml.Element(None, "intent-filter")
    a2 = axml.Element(None, "action")
    a2.attrs = [_attr("name", "android.provider.Telephony.SMS_RECEIVED")]
    filt2.children = [a2]
    recv.children = [filt2]
    app.children.append(recv)
    m.children.append(app)
    return axml.Builder().build([m])


NETWORK_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">api.insecure-bank.com</domain>
    </domain-config>
</network-security-config>
"""

STRINGS_XML = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">VulnBank</string>
    <string name="api_key">AIzaSyDfB5VulnerableKey1234567890abcd</string>
    <string name="stripe_secret">sk_live_51HrQp0VulnerableStripeSecret</string>
    <string name="default_password">Welcome123</string>
    <string name="server_url">http://api.insecure-bank.com/v1</string>
</resources>
"""

ASSETS_JSON = """{
  "endpoint": "http://api.insecure-bank.com/v1",
  "staging": "https://api.vulnbank.staging.internal/v1/ping",
  "token": "ghp_exampleGitHubToken000000000000000000"
}
"""


def build_apk(outdir):
    apk_path = os.path.join(outdir, "VulnerableBank.apk")
    manifest = build_android_manifest()
    so = make_elf64(NATIVE_DATA)
    dex = make_dex(DEX_STRINGS)
    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex)
        zf.writestr("lib/arm64-v8a/libvulnbank.so", so)
        zf.writestr("res/xml/network_security_config.xml", NETWORK_CONFIG)
        zf.writestr("res/values/strings.xml", STRINGS_XML)
        zf.writestr("assets/config.json", ASSETS_JSON)
        zf.writestr("sources/com/vulnbank/demo/MainActivity.java", MAIN_JAVA)
    return apk_path


def build_android_tree(outdir):
    """Plain source-tree fixture (like apktool output / Android project)."""
    tree = os.path.join(outdir, "VulnerableBank-Android")
    os.makedirs(os.path.join(tree, "res/xml"), exist_ok=True)
    os.makedirs(os.path.join(tree, "res/values"), exist_ok=True)
    os.makedirs(os.path.join(tree, "src/com/vulnbank/demo"), exist_ok=True)
    os.makedirs(os.path.join(tree, "lib/arm64-v8a"), exist_ok=True)
    with open(os.path.join(tree, "AndroidManifest.xml"), "w",
              encoding="utf-8") as fh:
        fh.write("""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.vulnbank.demo" versionCode="1" versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="26"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <application android:label="VulnBank" android:debuggable="true"
        android:allowBackup="true" android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:name=".OpenAccountActivity" android:exported="true"/>
    </application>
</manifest>
""")
    with open(os.path.join(tree, "res/xml/network_security_config.xml"),
              "w", encoding="utf-8") as fh:
        fh.write(NETWORK_CONFIG)
    with open(os.path.join(tree, "res/values/strings.xml"), "w",
              encoding="utf-8") as fh:
        fh.write(STRINGS_XML)
    with open(os.path.join(tree, "src/com/vulnbank/demo/MainActivity.java"),
              "w", encoding="utf-8") as fh:
        fh.write(MAIN_JAVA)
    with open(os.path.join(tree, "lib/arm64-v8a/libvulnbank.so"), "wb") as fh:
        fh.write(make_elf64(NATIVE_DATA))
    return tree


def build_ipa(outdir):
    ipa_path = os.path.join(outdir, "VulnerableBank.ipa")
    info_plist = plist.dumps(INFO_PLIST)
    macho = make_macho64(MACHO_PAYLOAD)
    with zipfile.ZipFile(ipa_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Payload/VulnBank.app/Info.plist", info_plist)
        zf.writestr("Payload/VulnBank.app/VulnBank", macho)
        zf.writestr("Payload/VulnBank.app/embedded.mobileprovision",
                    PROVISIONING_XML.encode("utf-8"))
    return ipa_path


def build_all(outdir):
    os.makedirs(outdir, exist_ok=True)
    apk = build_apk(outdir)
    ipa = build_ipa(outdir)
    tree = build_android_tree(outdir)
    print("built fixtures:")
    print("  %s" % apk)
    print("  %s" % ipa)
    print("  %s" % tree)
    return apk, ipa


if __name__ == "__main__":
    build_all(os.path.join(os.getcwd(), "masa-demo"))
