"""Detection rules for the Mobile App Security Analyzer.

Each rule targets an OWASP Mobile Top 10 (2023) category and carries a
legacy (2016) mapping. Rules are grouped by category. Programmatic checks
(manifest attributes, permissions, binary structure) are implemented in
apk.py / ipa.py / native.py and reuse the ids defined here as well.
"""

from .models import Rule

# ---------------------------------------------------------------- secrets
# OWASP M1 - Improper Credential Usage

SECRETS = [
    Rule("SEC-001", "Hardcoded AWS Access Key", "critical", "M1", "secrets",
         r"\bA[KS]IA[0-9A-Z]{16}\b",
         "A live AWS access key id (AKIA or ASIA) is embedded in the application. "
         "Anyone with the APK/IPA can extract it and use the associated IAM "
         "permissions.",
         "Remove the key, rotate any exposed credentials, and fetch "
         "credentials at runtime (e.g. from a secure backend or the OS "
         "keychain/Keystore)."),
    Rule("SEC-002", "Hardcoded Google API Key", "high", "M1", "secrets",
         r"\bAIza[0-9A-Za-z_\-]{33,}\b",
         "A Google API key is embedded in the binary. It can be extracted "
         "and abused (quota theft, paid API usage).",
         "Restrict the key by package name + SHA-1 fingerprint and serve it "
         "from a backend proxy."),
    Rule("SEC-003", "Hardcoded Stripe Secret Key", "critical", "M1", "secrets",
         r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b",
         "A Stripe secret/restricted key is embedded; extracting it grants "
         "full read/write access to the merchant account.",
         "Never ship secret keys in mobile apps. Route payments through a "
         "server-side SDK and rotate the key."),
    Rule("SEC-004", "Hardcoded GitHub Token", "critical", "M1", "secrets",
         r"\bgh[pousr]_[0-9A-Za-z]{20,}\b",
         "A GitHub personal access token is embedded in the application.",
         "Remove and revoke the token; use short-lived scoped tokens served "
         "from the backend."),
    Rule("SEC-005", "Hardcoded Slack Token", "high", "M1", "secrets",
         r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
         "A Slack API token is embedded in the application.",
         "Remove the token and authenticate through a backend service."),
    Rule("SEC-006", "Hardcoded API Key / Access Token", "high", "M1", "secrets",
         r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|"
         r"auth[_-]?token|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*"
         r"['\"][^'\"]{8,}['\"]",
         "An API key or access token is assigned a literal string value in "
         "code. Secrets embedded in client code are extractable from the "
         "binary and cannot be revoked individually.",
         "Store secrets on a backend and exchange them for short-lived "
         "session tokens; protect tokens at rest with the Keystore/Keychain."),
    Rule("SEC-007", "Embedded Private Key Material", "critical", "M1", "secrets",
         r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
         "Private key material (RSA/EC/OpenSSH) is embedded in the app or "
         "its resources. Anyone can decrypt data protected by the matching "
         "public key, or impersonate the signer.",
         "Generate keys on-device or store them in the OS keychain; never "
         "package private keys."),
    Rule("SEC-008", "Hardcoded JWT Token", "high", "M1", "secrets",
         r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
         "A signed JSON Web Token is hardcoded. Tokens expire, but a static "
         "token embedded in the binary is reusable by attackers and cannot "
         "be revoked per-device.",
         "Obtain tokens at runtime via authentication flows; store them in "
         "the Keystore/Keychain."),
    Rule("SEC-009", "Hardcoded Password", "high", "M1", "secrets",
         r"(?i)(?:(?<![0-9a-z])|^)(?:password|passwd|pwd|pin|passcode)\b"
         r"\s*[:=]\s*['\"][^'\"]{4,}['\"]",
         "A password or PIN is assigned a literal string value. Hardcoded "
         "passwords are shared across all installations and easily "
         "extracted.",
         "Require user-supplied credentials; enforce unique, high-entropy "
         "passwords verified against breach lists server-side."),
    Rule("SEC-010", "Hardcoded Username", "low", "M1", "secrets",
         r"(?i)\b(?:username|user[_-]?name|login)\b\s*[:=]\s*['\"][^'\"]{3,}['\"]",
         "A username/login is hardcoded, usually alongside hardcoded "
         "credentials.",
         "Remove hardcoded accounts; provision users through the normal "
         "registration flow."),
    Rule("SEC-011", "Hardcoded Firebase Project URL", "medium", "M1", "secrets",
         r"\bhttps://[a-z0-9-]{6,}\.firebaseio\.com\b",
         "A Firebase project URL is embedded. If security rules are "
         "misconfigured, the project data can be read/written by anyone.",
         "Audit Firebase security rules and move admin operations "
         "server-side."),
]

# ---------------------------------------------------------------- crypto
# OWASP M10 - Insufficient Cryptography

CRYPTO = [
    Rule("CRY-001", "Deprecated DES / 3DES Cipher", "high", "M10", "crypto",
         r"(?i)(?:DESede|DES/ECB|DES/CBC|3DES|kCCAlgorithmDES|kCCAlgorithm3DES|"
         r"CCCrypt(?![A-Za-z0-9_])|\bDES\b)",
         "DES and 3DES are legacy ciphers with a 56/112-bit effective key "
         "size, broken by modern brute-force and meet-in-the-middle attacks.",
         "Use AES-256 with a GCM/ChaCha20 authenticated mode."),
    Rule("CRY-002", "MD5 Hash Function", "high", "M10", "crypto",
         r"(?i)(?:MessageDigest\.getInstance\s*\(\s*['\"]MD5|CC_MD5|md5\s*\()",
         "MD5 is cryptographically broken (collision attacks) and must not "
         "be used for password hashing, signatures or integrity checks.",
         "Use SHA-256/384 or an HMAC for integrity; Argon2/scrypt/PBKDF2 "
         "for password hashing."),
    Rule("CRY-003", "SHA-1 Hash Function", "medium", "M10", "crypto",
         r"(?i)(?:MessageDigest\.getInstance\s*\(\s*['\"]SHA-?1|CC_SHA1|sha1\s*\()",
         "SHA-1 is deprecated; collision attacks (SHAttered) are practical.",
         "Migrate to SHA-256 or stronger."),
    Rule("CRY-004", "RC4 Stream Cipher", "high", "M10", "crypto",
         r"(?i)\bRC4\b",
         "RC4 is broken (bias attacks) and prohibited by TLS standards.",
         "Use AES-GCM or ChaCha20-Poly1305."),
    Rule("CRY-005", "ECB Encryption Mode", "high", "M10", "crypto",
         r"(?i)\b(?:AES|DES|DESede|Blowfish)/ECB\b",
         "ECB mode encrypts identical plaintext blocks to identical "
         "ciphertext, leaking data patterns (classic penguin problem).",
         "Use GCM/CBC with a random IV (prefer authenticated GCM)."),
    Rule("CRY-006", "Hardcoded Initialization Vector", "high", "M10", "crypto",
         r"(?i)\b(?:iv|init[_-]?vector|initialization[_-]?vector)\b\s*[:=]\s*"
         r"['\"][0-9A-Za-z+/=]{8,}['\"]",
         "A static IV makes CBC/CTR modes deterministic and enables "
         "plaintext recovery attacks.",
         "Generate a fresh random IV per encryption operation (AES-GCM "
         "includes an implicit nonce)."),
    Rule("CRY-007", "Hardcoded Salt", "medium", "M10", "crypto",
         r"(?i)\bsalt\s*[:=]\s*['\"][^'\"]{2,}['\"]",
         "A static salt defeats the purpose of per-user salting in key "
         "derivation; identical passwords yield identical keys.",
         "Generate a unique random salt per user and store it alongside "
         "the hash."),
    Rule("CRY-008", "Raw Password Used as Crypto Key", "high", "M10", "crypto",
         r"(?i)(?:SecretKeySpec|SecretKeyFactory)[^;\n]{0,40}\.[^;\n]{0,40}"
         r"getBytes\s*\(|new\s+SecretKeySpec\s*\(\s*['\"][^'\"]{4,}['\"]",
         "Using a password (or a hardcoded literal) directly as an AES key "
         "yields a low-entropy, brute-forceable key.",
         "Derive keys with PBKDF2/scrypt/Argon2 using a random salt and "
         "high iteration counts."),
    Rule("CRY-009", "Custom XOR Cryptography", "medium", "M10", "crypto",
         r"(?i)(?:xor\w*(?:encrypt|encode|decode)|data\[i\]\s*\^|"
         r"chars?\[i\]\s*\^|custom\s+(?:encrypt|encryption|cryptography|"
         r"encryptor))",
         "Custom XOR 'encryption' is trivially reversible with known "
         "plaintext and offers no real confidentiality. Homegrown "
         "cryptography is almost always broken.",
         "Use a vetted cryptographic library with authenticated "
         "encryption."),
    Rule("CRY-010", "Seeded Random for Security Use", "medium", "M10", "crypto",
         r"(?i)\bRandom\s*\(\s*\d+\s*\)",
         "A deterministically seeded PRNG produces predictable output; if "
         "used for keys, nonces or tokens it is guessable.",
         "Use SecureRandom / SecRandomCopyBytes with OS entropy."),
    Rule("CRY-011", "RSA Without OAEP Padding", "medium", "M10", "crypto",
         r"(?i)RSA/(?:ECB|None)/(?:PKCS1Padding|NoPadding)",
         "RSA with PKCS#1 v1.5 or no padding is vulnerable to Bleichenbacher "
         "and plaintext-recovery attacks.",
         "Use RSA-OAEP (or better, move to ECDH/AES-GCM)."),
    Rule("CRY-012", "Legacy Crypto Providers", "medium", "M10", "crypto",
         r"(?i)(?:Cipher\.getInstance\s*\(\s*['\"](?:RSA|DES|DESede|RC4|Blowfish)"
         r"|com\.sun\.crypto|CryptoPP|OpenSSL\s+crypto)",
         "Legacy ciphers or provider imports are present. Deprecated "
         "providers often ship weak defaults.",
         "Use the platform Keystore/Keychain-backed algorithms (AES-GCM, "
         "ChaCha20) and pin the algorithm parameters explicitly."),
]

# ---------------------------------------------------------------- storage
# OWASP M9 - Insecure Data Storage

STORAGE = [
    Rule("STO-001", "Sensitive Data in SharedPreferences (Android)", "high",
         "M9", "storage",
         r"(?i)(?:SharedPreferences|getSharedPreferences|getPreferences)\b"
         r"[^;\n]{0,200}\b(?:password|passwd|pwd|token|pin|ssn|credit|card|"
         r"api[_-]?key|secret|otp)\b|(?:password|token|pin|secret)\b"
         r"[^;\n]{0,80}putString\s*\([^;]*\b(?:password|token|pin|secret)\b",
         "Sensitive values are written to SharedPreferences, which are "
         "stored as world-readable XML files on disk (and extracted by any "
         "backup or rooted device).",
         "Store secrets in the Android Keystore (EncryptedSharedPreferences "
         "or Keystore-encrypted blobs)."),
    Rule("STO-002", "World-Readable/World-Writable File Mode", "high",
         "M9", "storage",
         r"MODE_WORLD_(?:READABLE|WRITABLE)",
         "World-readable/writable file modes expose data to every app on "
         "the device.",
         "Use MODE_PRIVATE; on modern Android, enforce scoped storage."),
    Rule("STO-003", "External Storage Used for App Data", "medium", "M9",
         "storage",
         r"(?i)(?:getExternalFilesDir|getExternalStorageDirectory|"
         r"Environment\.getExternalStorage|getExternalStoragePublicDirectory)",
         "Files on external/shared storage are readable by other apps and "
         "users; storing credentials or user data there is risky.",
         "Keep sensitive data in internal storage or the Keystore."),
    Rule("STO-004", "Plaintext SQLite Database", "medium", "M9", "storage",
         r"(?i)(?:SQLiteDatabase\.(?:openOrCreateDatabase|openDatabase)|"
         r"openOrCreateDatabase|createDatabase\s*\()",
         "SQLite databases are stored unencrypted on disk; any sensitive "
         "rows are recoverable from the device or backups.",
         "Use SQLCipher or encrypt sensitive columns; keep keys in the "
         "Keystore."),
    Rule("STO-005", "File Output Without Explicit Private Mode", "low",
         "M9", "storage",
         r"openFileOutput\s*\([^)]*\)",
         "openFileOutput defaults to MODE_PRIVATE, but explicit mode "
         "arguments should be audited; the default changed across API "
         "levels and files are visible in backups.",
         "Pass MODE_PRIVATE explicitly and exclude files from backups."),
    Rule("STO-006", "Sensitive Data in NSUserDefaults (iOS)", "high", "M9",
         "storage",
         r"(?i)(?:UserDefaults\.standard|NSUserDefaults|UserDefaults\(\)|"
         r"setObject:forKey:|standardUserDefaults)[^;\n]{0,200}\b(?:password|"
         r"passwd|pwd|token|pin|ssn|credit|card|secret|otp)\b",
         "NSUserDefaults stores data as plaintext property lists in the app "
         "sandbox, readable on jailbroken devices and recoverable from "
         "unencrypted backups.",
         "Store secrets in the iOS Keychain (kSecClassGenericPassword); use "
         "NSUserDefaults only for non-sensitive preferences."),
    Rule("STO-007", "Sensitive Data Written to Files (iOS)", "high", "M9",
         "storage",
         r"(?i)\b(?:write\(to:|writeToFile|writeString|writeData|"
         r"data\(using:\))\.?[^;\n]{0,120}\b(?:password|passwd|pwd|token|pin|"
         r"ssn|credit|secret)\b",
         "Sensitive values are written to plaintext files in the app "
         "container.",
         "Use the Keychain and Data Protection class A (file-level "
         "encryption)."),
]

# ---------------------------------------------------------------- network
# OWASP M5 - Insecure Communication

NETWORK = [
    Rule("NET-001", "Cleartext HTTP URL", "high", "M5", "network",
         r"\bhttp://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|10\.0\.0\.2|"
         r"192\.168\.|\[::1\]|0\.0\.0\.0|schemas\.android\.com|www\.w3\.org|"
         r"xml\.org)[^\s'\"<>]{5,}",
         "Plaintext HTTP traffic can be intercepted or modified on the "
         "wire (eavesdropping, session hijacking, injection).",
         "Use HTTPS exclusively and disable cleartext traffic in the "
         "network security config."),
    Rule("NET-002", "Cleartext Traffic Enabled in Manifest", "high", "M5",
         "network", None,
         "android:usesCleartextTraffic=\"true\" allows HTTP to every "
         "endpoint, bypassing the platform cleartext policy.",
         "Set usesCleartextTraffic=false and allow cleartext only for "
         "specific domains via networkSecurityConfig."),
    Rule("NET-003", "Cleartext Permitted in Network Security Config", "high",
         "M5", "network", None,
         "network_security_config.xml permits cleartext traffic (base "
         "config or domain config).",
         "Remove cleartextTrafficPermitted=true entries; migrate domains "
         "to HTTPS."),
    Rule("NET-011", "ATS Allows Arbitrary Loads (iOS)", "high", "M5",
         "network", None,
         "NSAppTransportSecurity.NSAllowsArbitraryLoads=true disables ATS "
         "for all connections, permitting cleartext HTTP.",
         "Remove the flag and use per-domain ATS exceptions with HTTPS "
         "only."),
    Rule("NET-016", "ATS Insecure HTTP Exception (iOS)", "medium", "M5",
         "network", None,
         "An ATS exception domain allows insecure HTTP loads "
         "(NSExceptionAllowsInsecureHTTPLoads).",
         "Serve the domain over HTTPS and remove the exception."),
    Rule("NET-004", "Certificate Validation Disabled (Trust-All)", "critical",
         "M5", "network",
         r"(?i)(?:checkServerTrusted\s*\(\s*[^)]*\)\s*\{\s*\}|TrustManager\[\]\s*"
         r"\{|trustAllCerts|TrustAllCerts|trustAllCertificates|"
         r"allowAllCertificates|setAllowsAnyHTTPSCertificate|"
         r"kCFStreamSSLAllowsAnyRoot|SecPolicySetTrust)|"
         r"(?:onReceivedSslError[^}]*proceed\s*\(\s*\))",
         "The app accepts any TLS certificate, making man-in-the-middle "
         "attack trivial (public Wi-Fi, DNS spoofing).",
         "Validate certificates against the system trust store and pin "
         "public keys."),
    Rule("NET-005", "Hostname Verification Bypassed", "critical", "M5",
         "network",
         r"(?i)(?:setHostnameVerifier|HostnameVerifier)[^;\n]{0,80}\{|\bverify\s*"
         r"\(\s*[^)]*\)\s*\{\s*return\s+true\b",
         "Hostname verification is disabled, so a valid certificate for "
         "any domain (e.g. attacker.com) is accepted.",
         "Keep hostname verification on and pin certificates."),
    Rule("NET-006", "Certificate Pinning Disabled in Code", "high", "M5",
         "network",
         r"(?i)(?:disableCertPinning|pinningEnabled\s*=\s*false|"
         r"sslPinning\s*=\s*false|allowInsecure|unpinning|"
         r"NSURLSession\s*\(configuration:\s*\.ephemeral\)[^;]*http)",
         "Certificate pinning is explicitly switched off, removing "
         "protection against MITM via compromised CAs.",
         "Enable pinning and pin the public key, not the certificate."),
    Rule("NET-007", "WebView Loading Cleartext HTTP", "high", "M5", "network",
         r"(?i)loadUrl\s*\(\s*['\"]http://",
         "The WebView loads content over cleartext HTTP.",
         "Serve content over HTTPS and forbid http:// in the WebView "
         "client."),
    Rule("NET-008", "Hardcoded IP Address Endpoint", "medium", "M5", "network",
         r"\bhttps?://\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:[/'\"]|\b)",
         "Backend endpoints are raw IP addresses - typical of test "
         "environments shipped by accident; also bypasses DNS-based "
         "controls.",
         "Use stable DNS hostnames (or a configuration mechanism) for "
         "production endpoints."),
    Rule("NET-009", "Token / API Key in URL", "high", "M5", "network",
         r"(?i)\bhttps?://[^\s'\"<>]*(?:access_token|api[_-]?key|auth[_-]?token|"
         r"session[_-]?id|token)=[^&\s'\"]+",
         "Credentials are transmitted as URL query parameters; they leak "
         "into logs, proxies and browser history.",
         "Send credentials in the Authorization header over TLS."),
    Rule("NET-010", "Hardcoded API Endpoint", "low", "M5", "network",
         r"\bhttps?://[a-z0-9.-]+\.[a-z]{2,}[:/][^\s'\"<>]{3,}",
         "A backend endpoint is hardcoded. Hardcoded endpoints complicate "
         "environment management and may point to staging servers.",
         "Centralize endpoint configuration (e.g. build config, remote "
         "config) and version the API."),
    Rule("NET-012", "WebView File Access Enabled", "medium", "M5", "network",
         r"(?i)(?:setAllowFileAccess|setAllowContentAccess)\s*\(\s*true\b",
         "WebView file access lets web content read files from the app "
         "sandbox.",
         "Disable file access (default since API 30); scope content to "
         "trusted origins."),
    Rule("NET-013", "Universal File URL Access in WebView", "high", "M5",
         "network",
         r"(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true\b",
         "file:// URLs can access any other origin's resources, enabling "
         "file theft via malicious web content.",
         "Never enable universal file access; serve content over https://."),
    Rule("NET-014", "WebView JavaScript Interface Exposed", "medium", "M5",
         "network",
         r"(?i)addJavascriptInterface\s*\(",
         "A JavaScript bridge exposes Java/ObjC methods to web content; "
         "with file access or untrusted content this enables RCE/data "
         "exfiltration.",
         "Remove the interface or expose it only to fully trusted content "
         "over HTTPS with strict origin checks."),
]

# ---------------------------------------------------------------- logging
# OWASP M6 - Inadequate Privacy Protections (log content leaks PII/credentials)

LOGGING = [
    Rule("LOG-001", "Sensitive Data Written to Logs", "medium", "M6",
         "logging",
         r"(?i)\b(?:Log\.[dvwei]|NSLog|os_log|print\(|console\.log|"
         r"Crashlytics\.log|Fabric\.log)[^\n]{0,120}\b(?:password|passwd|pwd|"
         r"token|pin|ssn|credit|card|secret|api[_-]?key|otp|authorization)\b",
         "Credentials or PII are written to logs, which are readable by "
         "other apps on Android (logcat) and exposed in device logs and "
         "crash reports.",
         "Never log sensitive values; redact secrets in debug logs and "
         "strip them from release builds."),
    Rule("LOG-002", "Verbose Debug Logging Left Enabled", "low", "M6",
         "logging",
         r"(?i)\bLog\.(?:v|d)\([^)]{0,60}\)|print\s*\(.*debug",
         "Verbose debug logging bloats logs and increases the chance of "
         "accidental sensitive data exposure.",
         "Gate debug logging behind BuildConfig.DEBUG."),
]

# ---------------------------------------------------------------- auth
# OWASP M3 - Insecure Authentication/Authorization

AUTH = [
    Rule("ATH-001", "WebView Password Saving Enabled", "high", "M3", "auth",
         r"(?i)setSavePassword\s*\(\s*true\b",
         "WebView password saving stores credentials in the shared "
         "WebView data store without protection.",
         "Disable password saving; rely on the OS credential manager."),
    Rule("ATH-002", "Insecure Client-Side Authorization Check", "medium",
         "M3", "auth",
         r"(?i)(?:isAdmin\s*\(\s*\)\s*\{[^}]{0,60}return\s+true|"
         r"isPremiumUser|hasAccess\b.{0,80}return\s+(?:true|1)\b)",
         "Authorization decisions are made purely client-side and can be "
         "bypassed by modifying the app or its storage.",
         "Enforce authorization server-side on every request."),
]

# ---------------------------------------------------------------- input
# OWASP M4 - Insufficient Input/Output Validation

INPUT = [
    Rule("INP-001", "SQL Injection in Database Query", "high", "M4", "input",
         r"(?i)\b(?:rawQuery|execSQL|compileStatement|query)\s*\(\s*"
         r"[^)]*\"[^\"']*\"\s*\+",
         "User-controlled values are concatenated into SQL statements, "
         "enabling SQL injection when any part of the string is tainted.",
         "Use parameterized queries (selectionArgs / bind arguments)."),
    Rule("INP-002", "Path Traversal via File Construction", "medium", "M4",
         "input",
         r"(?i)new\s+File\s*\([^)]*\)|Path\.combine\(|URL\.fileURLWithPath\(",
         "File paths are constructed dynamically; if any component comes "
         "from untrusted input (intents, deep links), arbitrary file "
         "access is possible.",
         "Sanitize and canonicalize paths; resolve within a fixed base "
         "directory."),
    Rule("INP-003", "Dangerous WebView File + JS Bridge Combination", "high",
         "M4", "input",
         r"(?i)(?:addJavascriptInterface)[\s\S]{0,600}?"
         r"(?:setAllowFileAccess\s*\(\s*true|"
         r"setAllowUniversalAccessFromFileURLs\s*\(\s*true)",
         "A JavaScript bridge combined with file access lets remote content "
         "invoke native code and read app files.",
         "Remove the bridge or the file access; keep only one channel and "
         "restrict it."),
]

# ---------------------------------------------------------------- privacy
# OWASP M6

PRIVACY = [
    Rule("PRI-001", "Device Identifiers Collected (IMEI/MAC/IDFA)", "medium",
         "M6", "privacy",
         r"(?i)(?:getDeviceId|getImei|getSubscriberId|getSimSerialNumber|"
         r"getMacAddress|identifierForVendor|advertisingIdentifier|"
         r"ASIdentifierManager)",
         "Hardware identifiers are collected; they cannot be reset by users "
         "and are considered PII under GDPR/CCPA.",
         "Use scoped identifiers (Advertising ID with consent, or app-"
         "scoped UUIDs)."),
    Rule("PRI-002", "Analytics/Tracking SDK Present", "info", "M6", "privacy",
         r"(?i)(?:FirebaseAnalytics|AppsFlyer|Adjust|Mixpanel|FacebookSdk|"
         r"FlurryAgent|AppMetrica)",
         "A tracking SDK is bundled. Confirm user consent is requested "
         "before collection and that PII is not shared.",
         "Implement consent management and data minimization."),
    Rule("PRI-003", "Tracking Without App Tracking Transparency", "medium",
         "M6", "privacy", None,
         "Advertising/device identifiers are used but the app does not "
         "declare NSUserTrackingUsageDescription (iOS 14+ ATT prompt) or "
         "equivalent consent flow.",
         "Add NSUserTrackingUsageDescription and request ATT consent "
         "before accessing the Advertising ID."),
]

# ---------------------------------------------------------------- config
# OWASP M8 - Security Misconfiguration

CONFIG = [
    Rule("CFG-004", "Debuggable Application", "high", "M8", "config",
         r"(?i)android:debuggable\s*=\s*[\"']true[\"']|"
         r"setFlags\s*\(\s*FLAG_DEBUGGABLE",
         "A debuggable build allows debugger attachment, which enables "
         "runtime memory inspection and method tampering.",
         "Ship release builds with debuggable=false."),
    Rule("CFG-001", "Exported Component Without Permission", "high", "M8",
         "config", None,
         "An application component (activity/service/receiver/provider) is "
         "exported to other apps without a permission requirement, letting "
         "any app on the device invoke it or feed it data.",
         "Remove android:exported or require a signature-level "
         "permission."),
    Rule("CFG-002", "Backup Enabled (allowBackup=true)", "medium", "M8",
         "config", None,
         "android:allowBackup=\"true\" lets adb/cloud backup extract app "
         "data including unencrypted preferences and databases.",
         "Set allowBackup=false or provide explicit backup rules that "
         "exclude sensitive data."),
    Rule("CFG-003", "Backup Enabled Without Backup Rules", "medium", "M8",
         "config", None,
         "Backup is implicitly enabled (allowBackup defaults to true) and "
         "no full-backup-content rules exist, so sensitive data may be "
         "included in backups.",
         "Set allowBackup=false or add res/xml backup rules excluding "
         "sensitive files."),
    Rule("SCP-001", "Outdated Target SDK Version", "medium", "M2",
         "supplychain", None,
         "The targetSdkVersion is below the current security baseline; "
         "legacy platform behaviors (scoped storage, permission "
         "autogrant, cleartext policy) are inherited.",
         "Raise targetSdkVersion to the latest stable API level and "
         "re-test."),
    Rule("PERM-001", "Dangerous Permission Declared", "medium", "M8",
         "permissions", None,
         "The app declares a dangerous-protection-level permission; "
         "confirm it is genuinely required by the app's functionality.",
         "Remove unused permissions; scope functionality to avoid "
         "dangerous grants."),
    Rule("PERM-002", "Dangerous Permission Declared But Unused", "low", "M8",
         "permissions", None,
         "A dangerous permission is declared but no matching usage was "
         "found in code - often copy-paste from templates, a sign of "
         "unvetted code or credential harvesting.",
         "Remove the permission or implement the functionality that "
         "requires it."),
    Rule("PERM-003", "Dangerous Permission Combination", "high", "M8",
         "permissions", None,
         "The combination of declared permissions enables invasive "
         "surveillance or fraud behavior (e.g. camera+mic+location, "
         "SMS+call-log+phone-state).",
         "Re-evaluate the app's legitimate need for the combination; "
         "remove unused parts."),
    Rule("PERM-004", "High-Risk Privilege Escalation Permission", "high",
         "M8", "permissions", None,
         "The app requests a permission that grants access to "
         "accessibility, overlay, install or device-administration "
         "capabilities - powerful primitives frequently abused by "
         "malware.",
         "Avoid these permissions entirely; if truly needed, justify and "
         "restrict their use."),
    Rule("CFG-005", "Staging/Test Endpoint in Production Build", "low", "M8",
         "config",
         r"(?i)\bhttps?://[a-z0-9.-]*(?:staging|sandbox|test|dev|"
         r"internal|qa)[a-z0-9.-]*\b|\.(?:test|dev|staging)\b",
         "A staging/test endpoint is reachable from the shipped app; it may "
         "leak production credentials or accept test data.",
         "Remove staging endpoints from release builds."),
]

# ---------------------------------------------------------------- binary
# OWASP M7 - Insufficient Binary Protections

BINARY = [
    Rule("BIN-002", "No Code Obfuscation/Minification Evidence", "low", "M7",
         "binary",
         r"(?i)(?:minifyEnabled|isMinifyEnabled|ProGuard|proguard|R8|"
         r"obfuscate|dashO|dexguard)",
         "No obfuscation/minification evidence found. Unobfuscated class "
         "names and strings make reverse engineering and secret hunting "
         "trivial.",
         "Enable R8/ProGuard with obfuscation for release builds."),
    Rule("BIN-003", "No Root/Jailbreak Detection Evidence", "low", "M7",
         "binary",
         r"(?i)(?:RootBeer|isRooted|rootDetection|detectRoot|jailbroken|"
         r"JBDetection|FridaServer|isJailbroken|tamper)",
         "No root/jailbreak or tamper detection evidence found, leaving the "
         "app unprotected against instrumented environments.",
         "Add root/emulator/tamper detection with a server-side risk "
         "signal."),
    Rule("BIN-004", "Mach-O Binary Not Encrypted", "medium", "M7", "binary",
         None,
         "The Mach-O main binary has no encryption info / cryptid=0. "
         "Unencrypted binaries are trivially disassembled and patched; "
         "App Store builds normally enable encryption.",
         "Distribute through the App Store (which encrypts binaries) and "
         "add integrity checks."),
]

# ---------------------------------------------------------------- supply chain
# OWASP M2 - Inadequate Supply Chain Security

SUPPLYCHAIN = [
    Rule("SCP-002", "Legacy Apache HTTP Client", "medium", "M2", "supplychain",
         r"(?i)(?:org\.apache\.http|DefaultHttpClient|AndroidHttpClient)",
         "The deprecated Apache HTTP client ignores modern TLS defaults and "
         "is unmaintained.",
         "Migrate to OkHttp/HttpURLConnection/URLSession with modern TLS."),
    Rule("SCP-003", "Dynamic Code Loading", "medium", "M2", "supplychain",
         r"(?i)(?:DexClassLoader|PathClassLoader|loadLibrary\s*\(\s*['\"][^'\"]+"
         r"\.so['\"]|dlopen\s*\()",
         "Code is loaded dynamically; if the source is remotely "
         "configurable or checksums are missing, an attacker can inject "
         "code.",
         "Verify integrity of loaded code and avoid remote code loading."),
    Rule("SCP-004", "Outdated Minimum OS Version", "medium", "M2",
         "supplychain", None,
         "The app supports very old OS versions (MinimumOSVersion below "
         "the security baseline), inheriting legacy platform security "
         "weaknesses.",
         "Raise MinimumOSVersion and require recent platform security "
         "patches."),
]

# ---------------------------------------------------------------- native
# Native/binary code analysis (Android .so / iOS Mach-O)

NATIVE = [
    Rule("NAT-001", "Unsafe String Function in Native Code", "high", "M7",
         "native",
         r"(?i)\b(?:strcpy|strcat|sprintf|gets|strncpy|strncat|vsprintf)\s*\(",
         "Unbounded string functions overflow buffers when input is "
         "untrusted, enabling memory corruption.",
         "Use strlcpy/snprintf/bounds-checked APIs or Rust/Swift managed "
         "types."),
    Rule("NAT-002", "Weak Cryptographic Primitive in Native Code", "high",
         "M10", "native",
         r"(?i)\b(?:MD5|DES|RC4|SHA-?1|3DES)\b",
         "A weak cryptographic primitive is present in native code.",
         "Replace with SHA-256/AES-256-GCM/ChaCha20 implementations."),
    Rule("NAT-003", "Command Execution in Native Code", "medium", "M7",
         "native",
         r"(?i)\b(?:system|popen|execl|execlp|execv|execvp|posix_spawn)\s*\(",
         "Shell/process execution from native code can lead to command "
         "injection when arguments are tainted.",
         "Avoid shell calls; use argument-array exec with strict "
         "validation."),
    Rule("NAT-004", "Weak Random in Native Code", "medium", "M10", "native",
         r"(?i)\brand\s*\(\s*\)\s*|srand\s*\(",
         "rand()/srand() produce predictable sequences unsuitable for "
         "cryptography or security tokens.",
         "Use getrandom()/arc4random()/SecRandomCopyBytes."),
    Rule("NAT-006", "Non-PIE Native Library", "medium", "M7", "native",
         None,
         "The native library is a non-PIE executable: ASLR does not apply, "
         "making exploitation of memory bugs significantly easier.",
         "Build as a PIE/shared library (default on modern NDKs)."),
    Rule("NAT-007", "No RELRO in Native Library", "medium", "M7", "native",
         None,
         "GNU_RELRO (and typically BIND_NOW) are missing: GOT entries are "
         "writable, enabling GOT-overwrite attacks.",
         "Link with -Wl,-z,relro,-z,now."),
    Rule("NAT-008", "Executable Stack in Native Library", "medium", "M7",
         "native", None,
         "The stack is marked executable (PT_GNU_STACK with PF_X), "
         "facilitating shellcode execution.",
         "Link with -Wl,-z,noexecstack."),
]

from typing import List, Optional, Tuple

ALL_RULES: Tuple[Rule, ...] = tuple(SECRETS + CRYPTO + STORAGE + NETWORK + LOGGING + AUTH + INPUT +
                                  PRIVACY + CONFIG + BINARY + SUPPLYCHAIN + NATIVE)

BY_ID = {r.id: r for r in ALL_RULES}


def get_rule(rule_id: str) -> Optional[Rule]:
    return BY_ID.get(rule_id)


def rules_for_category(category: str) -> List[Rule]:
    return [r for r in ALL_RULES if r.category == category]


def rules_for_owasp(owasp_id: str) -> List[Rule]:
    return [r for r in ALL_RULES if r.owasp == owasp_id]

