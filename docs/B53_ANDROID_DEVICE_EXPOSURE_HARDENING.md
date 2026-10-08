# B53 — Android Device Exposure Hardening

Status: `DEVICE-EXPOSURE BASELINE HARDENED / AUDIT COMPLETE / PHYSICAL DEVICE VALIDATION PENDING`

Evidence labels used below:

- **SOURCE-CONFIRMED** — established from reviewed source/configuration.
- **ARTIFACT-CONFIRMED** — established from the built release APK or merged manifest.
- **PHYSICAL-DEVICE-MEASURED** — established on Android hardware in this slice.
- **INFERRED** — follows from documented platform/runtime behavior but was not measured here.
- **NOT TESTED** — requires physical/OEM/root/lifecycle validation not available in this slice.

## 1. Executive summary

B53 audited Nova's Android component, storage, Keystore, backup/migration, Intent, VPN-service, subprocess, logging, diagnostics, sharing, UI, native-library, packaging, process-death, and restore boundaries. A real release APK was built and inspected.

No production private credential was found in the release APK. Nova debug activities and B45A credential BuildConfig fields are absent from release. Production VPN services are non-exported and require `BIND_VPN_SERVICE`; the only Nova release-exported activity is the launcher. Secret stores use app-private `noBackupFilesDir`, domain-separated Android Keystore aliases, AES-256-GCM randomized IVs, authenticated decryption, and fail-closed repositories.

Three narrow hardening changes were made:

1. **MEDIUM, debug-only:** exported `XrayDiagnosticsActivity` could accept profile-writing extras from any app in a debug installation. It now requires `android.permission.DUMP`, retaining shell/ADB operation while excluding ordinary apps.
2. **MEDIUM:** `allowBackup=false` does not uniformly disable Android 12+ OEM device-to-device transfer. Explicit deny-all legacy backup and API 31+ cloud/D2D extraction rules were added.
3. **LOW defense-in-depth:** production Shadowsocks forwarded third-party stdout/stderr to logcat. It now drains and discards both streams, eliminating a credential-adjacent native-output sink.

No VPN protocol, Smart Connect, manifest/certificate trust, B46/Hysteria, or transport selection behavior changed.

## 2. Threat model

| Actor | Covered guarantee |
| --- | --- |
| Normal malicious app | Cannot read sandbox files, invoke non-exported VPN services, or invoke the shell-protected debug profile importer |
| Physical user with unlocked device | May view ordinary UI and explicitly share sanitized support JSON; public keys may be explicitly copied |
| ADB/shell on debug-enabled device | Intentionally powerful; can launch `DUMP`-protected debug harnesses and inspect a debuggable process |
| Device owner/OEM migration agent | Explicit backup/D2D rules deny Nova data, but OEM behavior remains physical-device dependent |
| Root/compromised kernel | Out of confidentiality scope; can inspect process memory/files or instrument Keystore use |
| Remote network actor | Outside B53 except where error/log paths could expose local secrets |

Nova does not claim root-proof secrets, perfect JVM memory erasure, or protection from an operator who controls an unlocked debuggable build through ADB.

## 3. Method and evidence

- Reviewed all Android manifests, build types, component entry points, stores/factories, cryptography, runtime writers, process launchers, logs, models, diagnostics, and UI sharing/clipboard paths (**SOURCE-CONFIRMED**).
- Built `app-release-unsigned.apk`, SHA-256 `252dda4d9f78ecec6888ba4e276eff9c1d61d99b0465fa49d638e8a8b9f7f89f`, with target SDK 35/min SDK 26 (**ARTIFACT-CONFIRMED**).
- Inspected merged debug/release manifests, ZIP entries, DEX class descriptors/strings, generated release BuildConfig, resources/assets/native libraries, and secret markers (**ARTIFACT-CONFIRMED**).
- Consulted current official Android guidance for [exported components](https://developer.android.com/privacy-and-security/risks/access-control-to-exported-components), [Auto Backup and D2D](https://developer.android.com/identity/data/autobackup), [Android Keystore](https://developer.android.com/privacy-and-security/keystore), [app-specific storage](https://developer.android.com/training/data-storage/app-specific), [secure file sharing](https://developer.android.com/training/secure-file-sharing), and [log disclosure](https://developer.android.com/privacy-and-security/risks/log-info-disclosure).
- No Android device was used in this slice; all device-only rows are explicitly unmeasured.

## 4. Merged component inventory

### Release

| Component | Exported | Protection/input | Security result |
| --- | --- | --- | --- |
| `MainActivity` | Yes | Launcher intent; user-facing UI | Required external entry; no action-triggering secret extras found |
| AWG `GoBackend$VpnService` | No | `BIND_VPN_SERVICE` | App/system internal VPN boundary |
| `NovaXrayVpnService` | No | `BIND_VPN_SERVICE`; explicit internal extras/session handle | Other apps cannot start it |
| `ShadowsocksVpnService` | No | `BIND_VPN_SERVICE`; validates endpoint/method and loads credential internally | Other apps cannot start it |
| AndroidX `InitializationProvider` | No | Library initialization metadata | Not externally accessible |
| AndroidX `ProfileInstallReceiver` | Yes | `android.permission.DUMP` | Shell/tooling only; dependency component |

There are no Nova receivers or content providers in release. The merger adds a signature-level dynamic-receiver permission used by AndroidX. **ARTIFACT-CONFIRMED.**

### Debug additions

| Component | Exported | Protection/action |
| --- | --- | --- |
| `XrayDiagnosticsActivity` | Yes | Now `DUMP`-protected; can import real Xray profiles and start a test tunnel after UI action |
| `B45ASpikeActivity` | Yes | User buttons and system VPN consent gate starts/probes; debug credentials may exist in BuildConfig |
| `B45ASpikeVpnService` | No | `BIND_VPN_SERVICE` |
| `ShadowsocksAdapterValidationActivity` | Yes | User action provisions from external-files staging and can start validation tunnel |
| Compose `PreviewActivity` | Yes | Debug tooling dependency |

The latter two activities remain intentional debug attack surface: another app can open their UI, but audited sensitive actions require explicit user interaction/system VPN consent. A future debug-hardening slice may shell-protect every harness after confirming all physical workflows.

## 5. Debug/release separation

| Property | Debug | Release |
| --- | --- | --- |
| `debuggable` | True | Absent/false |
| Nova debug activities | Present | Absent from manifest and DEX |
| B45A service/spike classes | Present | Absent from DEX |
| B45A test host/port/method/key BuildConfig fields | Present structurally; values developer-local | Fields absent from release BuildConfig and DEX |
| Developer gateway overrides | Gitignored properties may populate debug/default fields | gateway fields generated empty; release manifest URLs forced to public production list |
| Local diagnostics file writer | Writes sanitized JSON to `filesDir` | `exportLatest()` no-op returning null |
| Normal support share | Sanitized JSON via explicit chooser | Same |
| Native spike binary | Debug source-set only when locally present | Absent |
| Logging | Debug harness logs exist | Production logs remain, but subprocess stdout/stderr is discarded |
| Backup policy | Deny all | Deny all |

Release absence is artifact-confirmed, not merely inferred from runtime flags.

## 6. Release APK inspection

The APK contains four DEX files, AndroidX/Kotlin/Bouncy Castle resources, Xray `geoip.dat`/`geosite.dat`, and AWG/Xray native libraries for packaged ABIs. No `libsslocal.so` was present in this build because the ignored production binary was not supplied; runtime eligibility must continue to fail closed in that condition.

DEX scans found zero occurrences of the three debug activity class names, B45A test host/key field names, or PEM private-key markers. Release BuildConfig contains `DEBUG=false`, empty developer gateway values, and public manifest origin URLs only. Public endpoints and embedded public verification material are not secrets. No suspicious production UUID/token/private-key literal was identified. **ARTIFACT-CONFIRMED.**

This scan is pattern- and structure-based, not a proof that arbitrary high-entropy data can never be secret. Reproducible CI artifact scanning is recommended.

## 7. Secret inventory

| Secret/security state | Storage/transit boundary |
| --- | --- |
| AWG private device identity | AES-GCM ciphertext in `noBackupFilesDir`; Keystore alias `net.pocvpn.client.identity.aesgcm.v1`; plaintext only for tunnel construction |
| Private-gateway AWG key | Separate encrypted identity file/alias `net.pocvpn.client.identity.privategateway.aesgcm.v1` |
| Xray REALITY UUID/key material | Endpoint-scoped encrypted file; alias `nova_xray_profile_key` |
| Xray TLS UUID | Endpoint-scoped encrypted file; alias `nova_xray_tls_profile_key` |
| Shadowsocks key | Endpoint-scoped encrypted file; alias `net.pocvpn.client.identity.shadowsocks2022.aesgcm.v1` |
| Ingress/relay profile/token | Encrypted file; alias `nova_ingress_profile_key` |
| Network fingerprint HMAC key | Android Keystore alias `nova_network_fingerprint_key`; not an encryption alias |
| Activation credential | UI/request memory; redacted model; no durable standalone credential store found |
| XHTTP secret-bearing session config | Process-local one-shot store; session ID crosses Intent, config does not |
| Shadowsocks runtime config | Plaintext app-private runtime file only during handoff; swept/deleted on startup, success, failure, and teardown |

## 8. Keystore boundary

Aliases are separated across AWG identity, private gateway, Xray REALITY, Xray TLS, Shadowsocks, ingress, and network fingerprint domains. `AndroidKeystoreAesGcmEncryptor` requests AES-256-GCM/NoPadding, encrypt/decrypt purposes, 128-bit authentication tags, and randomized IVs. Each encryption obtains `cipher.iv`; authenticated-decryption failure becomes a typed exception. **SOURCE-CONFIRMED.**

Modified ciphertext and wrong-key payloads fail authentication in fake/JVM repository tests; AndroidKeyStore-specific missing/invalidation/cross-device behavior is **NOT TESTED** physically. `getOrCreateKey()` can create a missing alias, but old ciphertext then fails GCM authentication; repositories do not treat that as permission to fabricate server-issued profiles. No plaintext fallback exists.

## 9. Filesystem and local-store boundary

All production factories reviewed place identity, profile, selected-gateway, routing, history, LKG, and private-gateway state in `applicationContext.noBackupFilesDir`. Debug local diagnostics use internal `filesDir`. Runtime Shadowsocks files use an app-private service directory. No broad storage permission, `QUERY_ALL_PACKAGES`, public directory, Downloads, or MediaStore write exists. **SOURCE-CONFIRMED.**

Secret profile stores persist ciphertext plus IV and validate length/version before decryption. Non-secret but security-relevant stores validate their formats and mostly use temp-file replacement. Older `renameTo()` stores write encrypted material to an app-private temp file; no evidence showed a cross-app disclosure. Their crash-atomicity is less uniform than `Files.move(ATOMIC_MOVE, REPLACE_EXISTING)`, but loaders reject truncation/corruption, so B53 does not refactor them for style. A focused future durability slice can fault-inject Android filesystem replacement behavior.

## 10. Backup and device-to-device migration

Before B53, `allowBackup=false` and `noBackupFilesDir` strongly protected cloud backup, but official Android guidance states that some Android 12+ manufacturers may still perform D2D transfer despite `allowBackup=false`. B53 adds:

- `android:fullBackupContent="@xml/backup_rules"` with deny-all API 23–30 domains;
- `android:dataExtractionRules="@xml/data_extraction_rules"` with deny-all cloud and device-transfer domains;
- retention of `android:allowBackup="false"`.

The resource schema and merged manifest were build-validated (**ARTIFACT-CONFIRMED**). Actual Google/OEM cloud and cable transfer behavior is **NOT TESTED**. Even if an OEM violates policy, ciphertext restored without its device-bound Keystore key fails closed; non-secret state is now also excluded to prevent stale authority.

## 11. Intent, Binder, and VPN-service boundary

All production VPN services are explicit, non-exported components. No custom exported Binder was found. Xray service extras contain typed control facts, endpoint/session identifiers, and routing facts. XHTTP uses `XhttpSessionConfigStore`: secret configuration remains process-local and is consumed exactly once; failure/disconnect removes pending entries. Shadowsocks Intent data contains endpoint/host/port/method but not the key; the service resolves the encrypted endpoint credential internally and checks signed-method equality.

Service restart cannot retrieve consumed XHTTP configuration and fails closed. Predictable in-process session IDs do not let another app fetch state because the service is non-exported and the map is process-local.

## 12. VPN lifecycle and process death

Provisioning applies durable state only after full response validation. File loaders reject malformed/partial data. Process death removes XHTTP one-shot state and active runtime state; restart reconstructs from validated durable stores, aligning with B52. A killed Shadowsocks process may leave its plaintext config, but the next start sweeps the exact known ephemeral filenames and refuses to continue when cleanup fails. Uninstall removes app-specific files; Android Keystore aliases are app-owned and expected to be removed, while explicit backup/D2D exclusion prevents Nova-managed restore.

Kill timing, OS service redelivery, uninstall/reinstall, and restored ciphertext behavior are **NOT TESTED** on hardware.

## 13. Temporary files and generated configurations

Shadowsocks writes the credential to `runtime_config.json` in app-private storage rather than argv. It deletes the file after confirmed handoff, on protect/spawn/handoff failure, on stop, and during stale-state sweep before a new start. Tests already cover stale plaintext cleanup and blocked cleanup. Socket paths carry no secrets in their names.

Xray configuration is rendered in memory and passed to the embedded library; no production Xray plaintext config file writer was found. AWG configuration is passed through the library/API. No evidence of secret `.tmp` files outside app-private directories was found.

## 14. Subprocess and native boundary

Shadowsocks argv contains binary path, config-file path, socket paths, and non-secret flags—not the key. B53 changes the production launcher to drain and discard stdout/stderr. Debug B45A retains separate debug evidence logging and is absent from release.

The embedded Xray/AWG libraries remain third-party native trust boundaries. Source wrappers do not dump their full configurations, but B53 did not rebuild/audit upstream native internals or attach logcat during fault cases. Native libraries can observe plaintext configuration in process memory by design; a compromised process/root adversary is out of scope.

## 15. Logging audit

Production Kotlin logging is concentrated in Xray and Shadowsocks service lifecycle/error paths. Reviewed messages expose state, public/non-secret endpoint facts, paths, transport method, or exception class/reason; profile types override `toString()` for key fields. Arbitrary `Throwable` logging remains primarily in debug bridges. No activation credential, AWG private key, Xray UUID, Shadowsocks key, bearer token, or imported package log interpolation was found.

The main concrete sink was third-party Shadowsocks stdout/stderr forwarding; it is removed. Some Xray outcome `reason` strings still reach logcat. Current constructors use controlled reasons, but maintaining closed typed reasons is recommended to prevent future upstream error text from becoming a log sink.

## 16. Secret-bearing models and `toString()`

Activation credentials/envelopes, Xray stored/runtime profiles, Shadowsocks key/credential/runtime target, and ingress profiles have explicit redacted representations. `AwgConfig` is a data class containing the private key and retains generated `toString()`; no production log/assertion/export call consuming the object was found (**SOURCE-CONFIRMED**, latent risk). `PersistedIdentity` prints ciphertext/IV array identities rather than plaintext but should still not be logged.

B53 avoids mechanical changes without a credible sink. A follow-up static lint rule should forbid logging types annotated/registered as secret-bearing and can then justify redacting remaining generated `toString()` implementations.

## 17. Diagnostics and support export

Runtime diagnostics use closed event types/tags. `buildSupportBundle` sanitizes every event tag value before serialization. The bundle additionally contains version/time, random session ID, network booleans/type, restriction class, selection/transport kinds, outcome, and the pseudonymous network fingerprint. These are intentionally support-visible; the fingerprint is privacy-sensitive correlation data, not a credential.

Existing sentinel tests cover UUID, Base64/key shapes, bearer headers, credential key/value text, PEM markers, URLs/queries, IPs, and endpoint-ID constraints. The sanitizer does not process fixed typed top-level fields because their types prevent arbitrary secret strings. No raw exception stack/message field exists in the bundle.

## 18. Release support export and file sharing

Release `LocalDiagnosticsExporter.exportLatest()` returns null; DEX confirms the release class is present as the no-op build-type implementation. The normal release “Export diagnostics” action calls `exportSupportBundleJson()` and shares small sanitized JSON as `Intent.EXTRA_TEXT` through an explicit chooser. There is no raw bundle path or filesystem URI.

Because no file is shared, FileProvider is unnecessary. No Nova provider exists. If future large exports become files, Android guidance requires a narrowly scoped non-exported FileProvider, `content://` URI, read-only temporary grant, sanitized file creation, and cleanup—never a raw path or broad files-directory mapping.

## 19. Clipboard, screen, and recents

Clipboard use is explicit and limited to AWG public keys (private-gateway client public key and debug identity public key). No automatic secret copy exists. Activation input and private-gateway server configuration are rendered in user-facing UI; the AWG private key is not rendered. Debug screens avoid rendering stored Xray/Shadowsocks credentials.

No `FLAG_SECURE` is set. The activation code can therefore appear in screenshots/recents while entered. B53 does not blanket-disable screenshots: whether activation codes warrant screen-scoped protection needs product/UX and physical recents validation. **NOT TESTED** on a device.

## 20. Package visibility and installed apps

The manifest uses only a launcher-intent `<queries>` declaration; `QUERY_ALL_PACKAGES` is absent. The installed-app list is queried for split-tunneling UI, not included in support bundle events, and no durable full application inventory was found. **SOURCE- and ARTIFACT-CONFIRMED.**

## 21. Native packaging and release behavior

Release uses extracted native libraries by deliberate prior decision. The APK includes AWG/Xray libraries and ABI variants, not debug spike libraries. `geoip.dat` and `geosite.dat` are public Xray datasets, not credentials. Release minification is disabled, so absence checks are especially meaningful: debug class names were not merely renamed; they were not compiled into release.

No crash-reporting or analytics SDK is declared. Thus Nova does not automatically attach process state/logs to a third party. **SOURCE- and ARTIFACT-CONFIRMED.**

## 22. Memory boundary

Plaintext keys necessarily exist briefly in managed/native memory while constructing or running tunnels. Nova cannot guarantee erasure from Kotlin/JVM strings, garbage-collected objects, native buffers, swap, or a compromised process. The design limits avoidable persistence: XHTTP config is one-shot; encrypted repositories decrypt on demand; activation input is cleared on successful activation; subprocess secrets are not argv/environment values; temporary config is deleted after handoff.

No long-lived diagnostic singleton retaining raw credentials was found. Physical heap/process inspection is **NOT TESTED**.

## 23. Uninstall, reinstall, restore, and clone

Official Android behavior removes app-specific internal files on uninstall. Keystore keys are application-bound; a reinstall/clone should not recover the old key. Explicit backup rules prevent supported backup/D2D transport of files. If ciphertext nevertheless appears without its key, GCM authentication fails and server-issued credentials are not regenerated as equivalent authority.

OEM clone tools, work profiles, signing-key changes, uninstall/reinstall, and D2D cable migration remain **NOT TESTED**. Nova makes no stronger claim than fail-closed source design plus artifact policy.

## 24. Concrete findings and fixes

| ID | Severity/scope | Evidence | Finding | Fix |
| --- | --- | --- | --- | --- |
| B53-01 | MEDIUM, debug only | Source + merged debug manifest | Exported Xray debug activity accepted credential-writing extras on launch | Require shell-held `android.permission.DUMP`; absent from release remains verified |
| B53-02 | MEDIUM | Official platform guidance + source | `allowBackup=false` alone may not stop API 31+ OEM D2D | Explicit deny-all legacy/cloud/device-transfer rules |
| B53-03 | LOW defense-in-depth | Source | Production third-party Shadowsocks stdout/stderr copied verbatim to logcat | Drain without logging |

No CRITICAL or HIGH release exposure was identified. Public endpoints, manifest keys, server public keys, and endpoint IDs were correctly classified as non-secret.

## 25. Remaining risks and gaps

1. Physical malicious-app invocation of debug components and `DUMP` enforcement is unmeasured.
2. OEM cloud/D2D behavior and wrong-device Keystore restoration are unmeasured.
3. Root/kernel/Frida/debugger compromise can observe process memory and is out of scope.
4. Activation UI screenshot/recents exposure needs device/product assessment.
5. Xray/AWG native internal logging was not dynamically fault-injected.
6. `AwgConfig` retains secret-bearing generated `toString()` without a current sink.
7. Older encrypted stores use `renameTo()`; Android crash/fault durability was not physically measured.
8. Release-specific unit tests cannot currently compile because shared `src/test` B45A tests reference debug-only production symbols; artifact build/lint succeeds and the existing `testRelease` exporter test could not execute through that task.
9. Static secret scanning is heuristic and should become reproducible CI policy.
10. No signed release artifact was installed; the audited APK is unsigned release output.

## 26. Tests and verification

- `processReleaseMainManifest` and `processDebugMainManifest`: passed; backup XML compiled and merged.
- `assembleRelease` including `lintVitalRelease`: passed, 53 tasks.
- Debug JVM suite: 1,735 tests, 1,734 passed, one known `EffectiveConfigDiffTest` baseline failure (`ClassCastException` at line 177).
- Release JVM suite: compilation blocked by pre-existing B45A source-set leakage from shared tests; not a B53 code failure.
- Focused B53 source-boundary tests cover backup declarations/rules, debug Xray permission, and removal of production stdout/stderr logging.
- Release APK/DEX scan: debug classes and B45A secret fields absent; no PEM private-key markers found.
- `git diff --check` and staged secret scan are required before commit.

## 27. Recommended follow-up slices

### B53-1P — Physical Android exposure validation

Install debug and signed release variants; attempt component invocation from a normal helper app versus ADB shell; exercise VPN permission, recents, logcat, process death, and stale config cleanup.

### B53-2P — Backup/restore and D2D matrix

Validate API 26–35 where available plus at least Google and one OEM transfer path. Confirm no Nova files transfer and wrong-device ciphertext fails closed.

### B53-3 — Security test/CI boundary

Fix shared debug-test source-set placement, run release tests in CI, add merged-manifest/APK assertions, high-entropy/known-pattern secret scanning, and a forbidden secret-type logging rule.

### B53-4 — Native and UI exposure validation

Fault-inject AWG/Xray/Shadowsocks native errors while capturing release logcat; decide screen-scoped `FLAG_SECURE` for activation/private configuration using product requirements.

## 28. Final decision gate

Decision: `DEVICE-EXPOSURE BASELINE HARDENED / AUDIT COMPLETE / PHYSICAL DEVICE VALIDATION PENDING`.

B53 is complete as an evidence-based source/artifact audit with three narrow fixes. It is ready for B54 because no unresolved finding requires changing B54’s restricted-network validation architecture. B53 physical follow-ups remain necessary before claiming measured protection against malicious apps, OEM migration, device restore, recents capture, or native fault logging. Nova does not claim resistance against root or kernel compromise.
