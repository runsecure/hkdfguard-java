# hkdfguard-java

HkdfGuard Key Wrapping and Secret Protection library for Java - the Java port of
[hkdfguard-dotnet](https://github.com/runsecure/hkdfguard-dotnet). Values encrypted by either
library decrypt with the other: the wire format, AAD rules, AES-GCM layout, span/metric names and
log event ids are identical.

Requires **Java 21** or later (the previous LTS) for every module except `hkdfguard-platform`,
`hkdfguard-keywrapping-v1`, `hkdfguard-securefile`, `hkdfguard-keywrapping-awskms`,
`hkdfguard-keywrapping-azurekeyvault`, `hkdfguard-keywrapping-googlekms` and
`hkdfguard-keywrapping-hashicorpvault`, which require **Java 25** (the current LTS). Cryptography is BouncyCastle; telemetry is the OpenTelemetry API; logging is SLF4J; native KMS
calls and the key-file checks use the Java FFM API, which is final only from Java 22 - hence those
modules' higher minimum. On Java 21, use the library with a `KeyWrapper` of your own in place of the
native one. Building the library needs JDK 25; CI also
runs the Java 21 modules' tests on a Java 21 runtime.

## Modules

| Artifact (`io.github.runsecure`)      | .NET assembly                        | Contents |
|---------------------------------------|--------------------------------------|----------|
| `hkdfguard-diagnostics`               | HkdfGuard.Diagnostics                | `HkdfGuardTelemetry`, span/attribute/event/metric names, `HkdfGuardLog` |
| `hkdfguard-abstractions`              | HkdfGuard.Abstractions               | `CryptoProvider`, `KeyWrapper`, `KeyRing`, `DataProtector`, ... ; `ProtectedCacheBase`, `ServiceNames`, `ProtectedConfigurationPurpose` |
| `hkdfguard-cryptoprovider-aesgcm256`  | HkdfGuard.CryptoProvider.AesGcm256   | `AesGcmCryptoProviderImpl`, `AesGcmCryptoProviderFactoryImpl`, `AesGcmPipelineDataProtectorImpl` |
| `hkdfguard-remote-common`             | -                                    | Internal: the strict JSON reader `hkdfguard-cache` takes secrets out of response bodies with, and the address, path, token and retry rules the two HashiCorp Vault modules share. Not an API for applications |
| `hkdfguard-platform`                  | -                                    | Internal: the OS calls and path checks `hkdfguard-keywrapping-v1` and `hkdfguard-securefile` share - Windows security descriptors and SIDs, Linux and macOS file status, the symbolic-link-following path walk (Java 25+). Not an API for applications |
| `hkdfguard-keywrapping-v1`            | HkdfGuard.KeyWrapping.V1             | `NativeHkdfKeyWrapperV1Impl` over the native KMS library, `NativeProcessHardening` (Java 25+) |
| `hkdfguard-securefile`                | HkdfGuard.SecureFile                 | `TrustedKeyFile`, `KeyFileTrust`: the native library's key-file location and content checks, in Java (Java 25+) |
| `hkdfguard-keywrapping-awskms`        | HkdfGuard.KeyWrapping.AwsKms         | `AwsKmsKeyWrapperImpl` over one symmetric AWS KMS key, through the AWS SDK for Java 2.x (Java 25+) |
| `hkdfguard-keywrapping-azurekeyvault` | HkdfGuard.KeyWrapping.AzureKeyVault  | `AzureKeyVaultKeyWrapperImpl` over an RSA wrapping key and an EC P-256 signing key in Azure Key Vault, through the Azure SDK for Java (Java 25+) |
| `hkdfguard-keywrapping-googlekms`     | HkdfGuard.KeyWrapping.GoogleKms      | `GoogleKmsKeyWrapperImpl` over one symmetric Google Cloud KMS key, through the Google Cloud client for Cloud KMS (Java 25+) |
| `hkdfguard-keywrapping-hashicorpvault` | HkdfGuard.KeyWrapping.HashiCorpVault | `HashiCorpVaultTransitKeyWrapperImpl` over one key in a HashiCorp Vault transit secrets engine, through `java.net.http`; `VaultTokenSource`, `StaticVaultTokenSource` (Java 25+) |
| `hkdfguard-dataencryptionkey`         | HkdfGuard.DataEncryptionKey          | `KeyRingImpl`, `KeyRingBuilder`, `DataEncryptionKeyImpl`, `DefaultFormatProviderImpl` |
| `hkdfguard-cache`                     | HkdfGuard.Cache                      | `ProtectedCacheImpl`, `ProtectedCacheCollectionImpl`; `RemoteSecretCache`, `SecretValueSink`, `SecretJsonBody`: the shared base of the secret-store caches below |
| `hkdfguard-cache-awssecretsmanager`   | HkdfGuard.Cache.AwsSecretsManager    | `AwsSecretsManagerSecretCacheImpl` over AWS Secrets Manager, through the AWS SDK for Java 2.x |
| `hkdfguard-cache-azurekeyvault`       | HkdfGuard.Cache.AzureKeyVault        | `AzureKeyVaultSecretCacheImpl` over one Azure Key Vault's secrets, through the Azure SDK for Java |
| `hkdfguard-cache-googlesecretmanager` | HkdfGuard.Cache.GoogleSecretManager  | `GoogleSecretManagerSecretCacheImpl` over one Google Cloud project's Secret Manager |
| `hkdfguard-cache-hashicorpvault`      | HkdfGuard.Cache.HashiCorpVault       | `HashiCorpVaultSecretCacheImpl` over one HashiCorp Vault KV secrets engine, through `java.net.http` |
| `hkdfguard-options`                   | HkdfGuard.Options                    | `HkdfGuardOptions`, `KeyFileOptions`, `OptionsValidationException` |
| `hkdfguard-spring-boot-starter`       | HkdfGuard.DependencyInjection, HkdfGuard.EncryptedConfiguration | Spring Boot 4 auto-configuration of the key ring, `ProtectedEnvironment`, and an Actuator health indicator |

The build has one more module, `hkdfguard-test-support`: `NativeTestEnvironment`, the helper the
native integration tests of several modules share (which provisioned service they use, and where key
files may be written), and `WindowsTempDirectory`, the folder the Windows key-file tests of
hkdfguard-securefile and the AWS KMS, Azure Key Vault, Google Cloud KMS and HashiCorp Vault transit
wrappers write to. It is
test code only - a test-scope dependency of hkdfguard-dataencryptionkey, hkdfguard-cache,
hkdfguard-securefile, hkdfguard-keywrapping-awskms, hkdfguard-keywrapping-azurekeyvault,
hkdfguard-keywrapping-googlekms and hkdfguard-keywrapping-hashicorpvault, compiled straight into hkdfguard-keywrapping-v1's tests (which it
depends on) - and is never published, signed or shipped in a release.

Naming: interfaces drop the .NET `I` prefix (`ICryptoProvider` -> `CryptoProvider`), and the classes
implementing them end in `Impl` (.NET's `AwsKmsKeyWrapper` is `AwsKmsKeyWrapperImpl`).
Plain data classes and static helpers that implement no interface (`HkdfGuardOptions`,
`KeyFileOptions`, `KeyFileTrust`, `TrustedKeyFile`) keep their .NET names.

## Example

```java
var ring = new KeyRingBuilder()
        .withServiceName("com.example.orders")
        .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl("com.example.orders"))
        .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
        .withKeyRefreshInterval(60)
        .withKeyFile(3, "/etc/myapp/wrapped-dek-v3.bin")
        .withEphemeralKey(100)
        .buildAsync()
        .join();

var protector = ring.createProtector(ProtectedConfigurationPurpose.forKey("ConnectionStrings:Admin"));
var result = new char[protector.getMaxDecryptedLength(encrypted)];
int length = protector.decrypt(encrypted, result);
```

## Differences from .NET, by design

- **Async** is `CompletableFuture`; there is no `CancellationToken` - cancel the future instead.
  Argument errors throw from the call itself; failures revealing a key complete the future
  exceptionally. A cache's `decryptAsync` reports every failure, a null name included, through its
  future. `InvalidDataException` for secrets is `InvalidSecretDataException`. Background refresh and
  rotation run on daemon background threads.
- **Disposal** is `close()` (blocking) and `closeAsync()`.
- **Spans** (`ReadOnlySpan<char>`/`Span<byte>`) become `CharSequence` for read-only text and
  `byte[]`/`char[]` for buffers. `TryGet...(out ...)` becomes `find...` returning `Optional`/`OptionalInt`.
- **Exceptions**: `ArgumentException` -> `IllegalArgumentException`, `ArgumentNullException` ->
  `NullPointerException`, `ObjectDisposedException`/`InvalidOperationException` ->
  `IllegalStateException`, `KeyNotFoundException` -> `NoSuchElementException`, `FormatException` ->
  `EncryptedFormatException`; `CryptographicException` and `AuthenticationTagMismatchException` keep
  their names.
- **Memory hygiene**: the JVM has no pinned or stack allocation for arrays, so zeroing erases the
  live copy of a secret but not copies a compacting GC may have left. Native KMS buffers are
  off-heap and zeroed before release. BouncyCastle's AES cipher also keeps an expanded key schedule,
  from which the key can be recovered; closing a session releases it rather than overwriting it, so
  it stays in the heap until the collector reuses that memory. Process hardening, which blocks core
  dumps and debugger attachment, is what keeps such copies out of reach.
- **Logging**: a null logger means the class's own SLF4J logger. .NET's Critical level is ERROR
  with the `CRITICAL` marker; the event id travels as the `hkdfguard.event_id` key-value.
- **Telemetry** goes to `GlobalOpenTelemetry` (read without latching a no-op), or to the instance
  given to `HkdfGuardTelemetry.setOpenTelemetry`.

## Encryption budget

With random 96-bit nonces, AES-GCM is safe for about 2^32 encryptions under one key (NIST
SP 800-38D). Each crypto provider counts the encryptions under its key, warns at 2^28, and
refuses to encrypt past 2^31 (`AesGcmCryptoProviderImpl.MAX_ENCRYPTIONS_PER_KEY`). Decryption is never limited.

That count is kept per process, by design. It is exact for the key an application should encrypt
with at runtime: an ephemeral key, generated at startup and held only in that process's memory, so
no other process or restart ever adds to its use. Key files are different. They carry what the
deployment pipeline encrypted and are meant to be decrypted at runtime; every process that loads a
key file, and every restart, starts a fresh count for it.

**For encrypt operations, add an ephemeral key** at a version above every key file
(`KeyRingBuilder.withEphemeralKey(2)` beside `withKeyFile(1, ...)`). New values are then encrypted under it, while the pipeline's values still decrypt
under their key files. A value encrypted under an ephemeral key can't be decrypted once the process
exits, which suits caches and other in-process data; never persist it.

If an application does encrypt values that must outlive the process under a key file, its
encryptions under that file are not counted together across instances and restarts. Bound them by
deploying a new key file at a higher version regularly.

## Configuration

`hkdfguard-options` lets configuration describe the ring. `HkdfGuardOptions` is a JavaBean, so a
binder such as Spring's `@ConfigurationProperties` or Jackson fills it directly; without one,
`HkdfGuardOptions.fromMap` reads a parsed section, matching keys ignoring case, `_` and `-`, so a
.NET `appsettings.json` `HkdfGuard` section reads unchanged. An unknown key is an error, unlike
.NET's binder, so a misspelt setting can't silently fall back to a default. `requireValid()`
reports every problem at once, and `applyTo` copies the settings onto a builder:

```java
var options = HkdfGuardOptions.fromMap(settings).requireValid();
var ring = options.applyTo(new KeyRingBuilder())
        .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl(options.getServiceName()))
        .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
        .buildAsync()
        .join();
```

## Spring Boot

Add `hkdfguard-spring-boot-starter` (Spring Boot 4.1) and configure the ring under `hkdfguard`:

```yaml
hkdfguard:
  service-name: com.example.orders
  key-refresh-interval: 60
  key-files:
    - version: 3
      path: /etc/myapp/wrapped-dek-v3.bin
  ephemeral-keys: [100]
```

- **The ring** is built at startup only when `hkdfguard.service-name` is set, and closed with the
  context. Invalid settings, or a misspelt property under `hkdfguard`, fail startup with every
  problem listed. Inject it as `KeyRing` (or `KeyRingImpl` for `createProtector`).
- **The key wrapper** is the native one for the configured service, created when
  `hkdfguard-keywrapping-v1` loads: Java 25, run with `--enable-native-access=ALL-UNNAMED`. On Java
  21, or to use another KMS, declare a `KeyWrapper` bean. Declaring a `CryptoProviderFactory`,
  `EncryptedFormatProvider`, `HkdfGuardOptions` or `KeyRing` bean likewise replaces that part.
- **Protected configuration:** a `ProtectedEnvironment` bean reveals configuration values that
  hold protected secrets, in any property source (`application.yml`, environment variables, a
  config server). It is the Spring counterpart of .NET's `ProtectedConfigurationRoot`: the
  configuration only ever holds the `enc::v{n}::...` ciphertext, and `decrypt` reads the property
  fresh on every call, decrypting into a buffer you zero when done. Nothing is cached, so a refreshed
  property takes effect immediately, and no secret lands in an immutable `String`; `@Value` and
  `getProperty` still return the ciphertext.

  ```java
  var maxLength = protectedEnvironment.findMaxDecryptedLength("spring.datasource.password").orElseThrow();
  var password = new char[maxLength];
  try {
      var length = protectedEnvironment.decrypt("spring.datasource.password", password);
      // use password[0..length)
  } finally {
      Arrays.fill(password, '\0');
  }
  ```

  Each value is bound to the property name it is read by, so a value copied to another property
  fails to decrypt. The name is used exactly as given (ignoring ASCII case), so the pipeline must
  encrypt for the same name the application reads: use Spring's canonical form,
  `my-service.api-key`. Spring would also find that value as `my-service.apikey`, but it would not
  decrypt under that spelling. An environment variable (`MY_SERVICE_API_KEY`) holding a value
  encrypted for `my-service.api-key` decrypts under that name.
- **Health:** with Actuator, `/actuator/health` gains an `hkdfguard` component that encrypts and
  decrypts a random probe with the current key. It reports `DOWN` when that key can't protect new
  values, most often because it failed closed after its KEK was revoked or became unreachable.
  It never calls the KMS. Its details are `currentVersion` (the key checked) and, when it is
  `DOWN`, `error`: a fixed message when the probe doesn't decrypt to what was encrypted, or, when
  the check throws, the exception's class and message (added by Spring's
  `AbstractHealthIndicator`). No key material, probe or ciphertext is reported. Turn it off with
  `management.health.hkdfguard.enabled=false`.

## Native access

`hkdfguard-keywrapping-v1` calls the native KMS library through FFM, a restricted API, and
`hkdfguard-securefile` (which the AWS KMS, Azure Key Vault, Google Cloud KMS and HashiCorp Vault transit wrappers read key files through) makes its
owner and permission checks through FFM too. The checks both share - security descriptors and SIDs
on Windows, file status and the path walk on Linux and macOS - are made by `hkdfguard-platform`,
which both depend on. On the class path, run with `--enable-native-access=ALL-UNNAMED`. On the module
path, grant each of these modules you use and `hkdfguard-platform`:

```text
--enable-native-access=io.github.runsecure.hkdfguard.keywrapping.v1,io.github.runsecure.hkdfguard.platform
--enable-native-access=io.github.runsecure.hkdfguard.securefile,io.github.runsecure.hkdfguard.platform
```

The Google Cloud KMS wrapper's gRPC transport loads a native library too; see
[Wrapping under Google Cloud KMS instead](#wrapping-under-google-cloud-kms-instead).
 The native library is installed separately and
loaded only from its verified location, exactly as in .NET (path ACLs, Authenticode signer/root/EKU
and PE checks on Windows, and after loading, that the module Windows mapped is the verified file;
ownership, code signature and dyld checks on macOS; ownership, the
dynamic linker's environment, where it would find every dependency (asked before loading) and
every loaded dependency on Linux).

Installed locations:

| Platform | Native library                                              | Command-line tool                        |
|----------|-------------------------------------------------------------|------------------------------------------|
| Windows  | `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll`                  | `%ProgramFiles%\HkdfGuard\v1\hkdfguard.exe` |
| Linux    | `/usr/lib/<multiarch>/libhkdfguard.so.1` or `/usr/lib64/libhkdfguard.so.1` (the `libhkdfguard1` package; `hkdfguard-libs` on RPM distributions); x64 and arm64 | `/usr/bin/hkdfguard` |
| macOS    | `/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib` or `~/.hkdfguard/v1/` | `hkdfguard`, beside the library |

On **Windows**, after the location, ACL, signer and PE checks have all passed, a second
Authenticode verification checks every certificate in the signer's chain for revocation, once per
process, and may fetch revocation information over the network. Only a definite "revoked" refuses
the load; if revocation servers can't be reached, or give no answer, the library loads, so a host
with no network still starts. On a host whose network silently drops traffic rather than refusing
it, the first load can stall once until the revocation lookup times out.

On **macOS**, `MacOsNativeLibraryLoader` uses the system install whenever it exists, and the
per-user install only when there is none. `~` is the effective user's home from the account
database (`getpwuid_r`), never the `user.home` property, which `-Duser.home` on the command line
could point anywhere; with no usable entry, only the system install is considered. Besides the
location, ownership and Developer ID signature checks, the library's own version - its
`LC_ID_DYLIB` current version, in the Mach-O header the signature covers - must be at least
`MINIMUM_LIBRARY_VERSION` (0.9.0), so an older release, though genuinely signed, is refused. On
Windows the same 0.9.0 floor applies to `HkdfGuard.dll`'s signed version resource; a DLL with none
is refused.

Certificate revocation is not checked on macOS. Apple's code-signing check can be told to require
it, but then a host that can't reach Apple's servers couldn't load the library, turning a network
outage into a service outage. What stands in for it: the signature must come from HkdfGuard's
Developer ID and team, the system install can only be written by an administrator, and the minimum
version refuses older genuine releases. The accepted risk is a stolen HkdfGuard signing
certificate: whoever holds it, and can also write an install location (an administrator for the
system install, the same user for a per-user one), could sign and plant a library of their own,
whatever version it claims. The answer to such a compromise is Apple revoking the certificate and a
new release; until consumers update, the system install's admin-only location is the barrier, so
prefer it to a per-user install in production.

On **Linux**, `LinuxNativeLibraryLoader` uses the package's file in the Debian multiarch directory
(`/usr/lib/x86_64-linux-gnu` or `/usr/lib/aarch64-linux-gnu`) if it is there, otherwise the one in
`/usr/lib64`. Only "nothing is there" moves on; a location that can't be examined is refused.
The file's content is not pinned: verify a release's Sigstore attestation (`cosign` or
`gh attestation verify`) before installing the package, so path integrity is what the loader
enforces. Before loading, it requires all of the following:
- Every directory on the path, every symbolic link followed, and the file itself are owned by root,
  and no directory or file is writable by its group or by others. Links are followed one component
  at a time and each target is checked where it lies, so `/lib -> usr/lib` passes and a link into a
  user's directory does not.
- The dynamic linker's environment is checked. The library is loaded by its
  verified absolute path, which is never searched for, but its dependencies are found by name - and
  `libtss2-esys` receives every ECDH shared secret. So every `LD_LIBRARY_PATH` directory, and every
  path-named `LD_PRELOAD` or `LD_AUDIT` object, must pass the same path checks, and none may be
  relative, empty (the working directory) or use `$ORIGIN`-style tokens. Both the environment the
  process started with (`/proc/self/environ`) and the current one are checked.
  This check catches a misconfigured environment. It can't stop someone who controls the
  service's environment: whatever `LD_PRELOAD` or `LD_AUDIT` loads runs when the process starts,
  before the check, and can hide from it. Protect the service's environment (its unit file,
  container spec or launch configuration) as carefully as its binaries.
- The process's own dynamic linker (its `PT_INTERP`, which must pass the same ownership checks) is
  asked in list mode (`ld.so --list`, what `ldd` uses), under the `LD_LIBRARY_PATH` and
  `LD_PRELOAD` the process started with and nothing else, where it would find every library
  `libhkdfguard.so.1` pulls in. Each must pass the same ownership checks, so a dependency found
  somewhere writable is refused before any of its code runs, and a dependency it can't find refuses
  the load. Preloaded objects are listed too, including ones `LD_PRELOAD` names without a path.

On macOS the loader also refuses while `DYLD_INSERT_LIBRARIES`, `DYLD_FRAMEWORK_PATH`,
`DYLD_VERSIONED_LIBRARY_PATH`, `DYLD_VERSIONED_FRAMEWORK_PATH` or `DYLD_IMAGE_SUFFIX` is set: each
makes dyld inject code or substitute a library the native library calls with every DEK. The same
limit applies - dyld acts on them at process start - and the real protection is a host signed with
the Hardened Runtime, which makes dyld ignore them.

After loading, `dladdr` must place the library's export in the verified file, and every object in
its dependency closure, read from each file's `DT_NEEDED` entries, must be bound to a file that
passes the path checks. That catches a dependency the process had already loaded from somewhere
else under the same name; the library is then unloaded and the load refused. A failed check throws
`SecurityException`, a missing package `NativeLibraryNotFoundException`, and an architecture with
no package `UnsupportedOperationException`; there is no fallback and no override. Two things are
outside the loader's reach: the TPM transport module tpm2-tss loads at the first TPM call, which
only the environment check covers, and the JVM's own injection points (`-agentpath`, `-javaagent`,
`JAVA_TOOL_OPTIONS`), which need a protected service command line and environment on every
platform.

**Key files are read through the native library.** `KeyRingBuilder` reads every key file through
its key wrapper (`KeyWrapper.readKeyFileAsync`). `NativeHkdfKeyWrapperV1Impl` reads it with the
native library's `hkdfguard_open_file`, which returns the bytes still wrapped (it never unwraps or
touches a KEK) and refuses a file that is missing, unreadable, the wrong size for a wrapped DEK,
not a valid wrapped payload, or that holds what looks like an unwrapped key (32 raw bytes, or their
hex or base64) - and a file whose location isn't trusted: a symbolic link, junction or other
reparse point, an 8.3 short name, a UNC, mapped or SUBST drive, or a file or folder another account
could write or replace. Each refusal names the path and the native status, and is an
`IllegalArgumentException` for -1 (invalid argument) and otherwise an `IOException`:
`NoSuchFileException` (-32), `AccessDeniedException` (-33 access denied, -39 untrusted location),
`InvalidKeyFileException` (-35 too short, -36 too long, -37 plaintext key, -38 malformed), or a
plain `IOException` (-34 and anything else). `KeyWrapper.readKeyFileAsync` has no default, so
any other key wrapper must read key files itself, and must refuse one another account could have
written or replaced. `hkdfguard-securefile`'s `TrustedKeyFile.readAsync` does that in Java, by the
same rules and with the same exceptions, for key wrappers with no native library to read through;
`AwsKmsKeyWrapperImpl`, `AzureKeyVaultKeyWrapperImpl`, `GoogleKmsKeyWrapperImpl` and
`HashiCorpVaultTransitKeyWrapperImpl` read key files with it.

**Status codes.** The Windows, Linux and macOS native libraries share one `HKDFGUARD_ERR_*` table,
number for number, and every failure message names the status and what it means:

| Status | Name | | Status | Name |
|---|---|---|---|---|
| 0 | OK | | -20 | PROCESS_HARDENING_FAILED |
| -1 | INVALID_ARGUMENT | | -32 | FILE_NOT_FOUND |
| -2 | BUFFER_TOO_SMALL | | -33 | FILE_ACCESS_DENIED |
| -3 | PROVIDER_UNAVAILABLE | | -34 | FILE_IO |
| -4 | PROVIDER_ERROR | | -35 | FILE_TOO_SHORT |
| -5 | CRYPTO_ERROR | | -36 | FILE_TOO_LONG |
| -6 | INTERNAL_ERROR | | -37 | FILE_PLAINTEXT_KEY |
| -8 | INVALID_SERVICE_NAME | | -38 | FILE_MALFORMED |
| -9 | POLICY_INVALID | | -39 | FILE_UNTRUSTED |
| -10 | PAYLOAD_MALFORMED | | -64 | WIN_GROUP_INVALID |
| -11 | PAYLOAD_AUTH_FAILED | | -96 | MAC_ACCESS_CONTROL_CREATION_FAILED |
| -12 | PAYLOAD_UNSUPPORTED | | -97 | MAC_KEY_GENERATION_FAILED |
| -13 | PAYLOAD_VERSION_REFUSED | | -98 | MAC_KEYCHAIN_WRITE_FAILED |
| -16 | KEK_FINGERPRINT_MISMATCH | | -99 | MAC_KEK_VERIFICATION_FAILED |
| -17 | KEK_NOT_FOUND | | -100 | MAC_KEYCHAIN_READ_FAILED |
| -18 | KEK_ACCESS_DENIED | | | |
| -19 | KEK_INVALID | | | |

Every other negative code (-7, -14..-15, -21..-31, -40..-63, ...) is reserved.

## Process hardening

DEKs pass through your process's memory, so a crash dump, or another process of the same user
attaching a debugger or reading that memory, could recover them. `NativeProcessHardening.apply()`
(in `hkdfguard-keywrapping-v1`) calls the native library's `hkdfguard_harden_process_with_flags`
to close that off, on every platform:

| Platform | What it does |
|---|---|
| Windows | Crash reports leave out the heap, and the process's and its threads' access lists are replaced so only SYSTEM can read or write its memory, inject threads or duplicate its handles. Its own account keeps only query, synchronize and terminate. |
| Linux | Core dumps off (hard limit included), and the process marked non-dumpable, which also stops ptrace and `/proc/<pid>/mem` access by the same user. |
| macOS | Core dumps off and debugger attachment denied. Whether code can be injected depends on the host executable's code signature, which the library checks but can't change. |

Neither the native library nor any machine policy does this for you: it changes process-wide
state your application owns, so it is opt-in. Call it once, early in startup - first thing in
`main`, before starting a framework or worker threads on Windows, and after any privilege drop on
Linux:

```java
public static void main(String[] args) {
    NativeProcessHardening.apply();   // throws IllegalStateException if it fails: don't start
    SpringApplication.run(MyApplication.class, args);
}
```

It loads and verifies the native library first, so it can also throw what loading throws
(`NativeLibraryNotFoundException`, `SecurityException`, or `UnsupportedOperationException` on a
platform without one). Debuggers, `jcmd`, `jstack` and other attach-based tools, and crash dumps
stop working for the process. It is a same-user barrier: it does not stop administrators, root,
SYSTEM, `SeDebugPrivilege`, `CAP_SYS_PTRACE` or the kernel, and it does not keep memory out of
swap, the page file or hibernation files. Nor does it stop the JVM's own injection points
(`-agentpath`, `-javaagent`, `JAVA_TOOL_OPTIONS`), which act before `main`.

`NativeProcessHardening.apply(ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE)` is the strict
form the native command-line tools use: it fails unless no other process of the same user can
debug or inject into this one.

- **Windows:** it also closes threads started later, and everything else the process creates
  afterwards without its own security descriptor (child processes, named pipes, named events), to
  its own account. Use it in a service that shares no objects with other processes by name.
- **macOS:** it fails unless the host executable is signed with the Hardened Runtime and without
  the `get-task-allow` or `DYLD_*` entitlements, so an unsigned host, or a JDK launcher whose
  entitlements allow either, can't use it (check with `codesign -d --entitlements - <java>`).
  Without it, a weak signature is only logged.
- **Linux:** it adds nothing; the plain call already guarantees it.

**Java on Windows:** the plain call closes the threads that exist when it runs, and threads started
later keep the default access, which lets other processes of the same user read and change their
registers. A Java application can't call it "before starting threads": the JVM starts threads of its
own before `main` runs (garbage collector, JIT compiler, reference handler and finalizer threads),
and keeps adding more whenever it needs them - more compiler threads, the common `ForkJoinPool`,
virtual-thread carriers, a framework's executors. Calling it first thing in `main` covers the
threads that exist then, not the ones added later, so **use `REQUIRE_PROTECTED_SIGNATURE` for a
Windows service**: it closes later threads too.

The Spring Boot starter deliberately has no property for this: auto-configuration runs after
Spring has started its own threads and loaded the application's classes, too late to be the
"first thing at startup" it should be, so call it in `main` before `SpringApplication.run`.

## Wrapping under AWS KMS instead

`AwsKmsKeyWrapperImpl` (artifact `hkdfguard-keywrapping-awskms`) is a `KeyWrapper` over one
symmetric AWS KMS key. Use it in place of `NativeHkdfKeyWrapperV1Impl` wherever a wrapper is taken.
Every call is a KMS request, authorized by the process's IAM credentials and recorded in CloudTrail:

```java
// The application builds the client, keeps it open while anything uses the wrapper, and closes it.
var kms = KmsAsyncClient.builder()                       // default credential and region chain
        .httpClientBuilder(NettyNioAsyncHttpClient.builder())
        .build();
var wrapper = new AwsKmsKeyWrapperImpl(kms,
        "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        Map.of("purpose", "my.service"));
```

- `generateAndWrapAsync` calls `GenerateDataKeyWithoutPlaintext` for an AES-256 key, so the
  plaintext DEK never leaves KMS on that call. `wrapAsync` calls `Encrypt` and `unwrapAsync` calls `Decrypt`.
- The key is pinned on every `Decrypt`. A symmetric ciphertext names its own key, and without the pin
  a substituted key file wrapped under any other key the principal may use would still be revealed.
  Prefer a key ARN to an alias: `Decrypt` resolves an alias when it is called, so re-pointing the
  alias makes DEKs wrapped under the old key unreadable. KMS's automatic key rotation keeps the
  ARN and needs nothing here.
- The optional encryption context is KMS's AAD. It is bound into every wrapped DEK, required again
  to reveal it, and can be required by the key policy (`kms:EncryptionContext:purpose`). CloudTrail
  logs it in plaintext, so it must never hold a secret.
- Failures complete the future with a `CryptographicException` naming KMS's error code (for example
  `AccessDeniedException` or `InvalidCiphertextException`) and the HTTP status, with the AWS
  exception as its cause; argument errors throw from the call. Cancellation - a cancelled future, or
  the SDK's `AbortedException` - is passed on unwrapped, and cancelling a returned future cancels its
  KMS request. A failed unwrap zeroes the caller's buffer.
- Key files are read only from where no untrusted account could have written or replaced them, by
  the native library's rules, checked in Java by `hkdfguard-securefile`: on Windows, a local fixed
  drive, reached through no link, junction or substituted drive, with the file and every folder
  above it owned and modifiable only by SYSTEM, Administrators or TrustedInstaller; on Linux and
  macOS, the file and every directory above it owned by root and writable by no one else, following
  only root-owned links. A `KeyFileTrust` passed to the constructor adds the deployment's own account
  or group. A file that looks like an unwrapped key is refused too. A KMS ciphertext is about 184
  bytes, well inside `WrappedKeyLimits.MAX_BYTES`.
- Plaintext the wrapper can reach is zeroed: its copy of the key sent to `Encrypt`, and the array
  inside the `SdkBytes` `Decrypt` returns. The SDK's JSON request and response bodies, and the array
  it decodes the response's base64 into before copying it, aren't exposed, so they can't be.
- The principal needs `kms:Encrypt`, `kms:Decrypt` and `kms:GenerateDataKeyWithoutPlaintext` on the key.
  A process that only reads existing key files needs only `kms:Decrypt`.

**Dependencies.** The module depends on `software.amazon.awssdk:kms`, at the version the
`software.amazon.awssdk:bom` in this build's parent POM pins, but excludes the SDK's two default HTTP
clients (`netty-nio-client` and `apache5-client`, which the SDK otherwise adds at run time): the
application builds the client, so it chooses the HTTP client, and no consumer gets Netty's
dependency tree on its class path without asking for it. Add the one you build your
`KmsAsyncClient` with - `software.amazon.awssdk:netty-nio-client` or
`software.amazon.awssdk:aws-crt-client` - at the same SDK version, ideally by importing the same
`software.amazon.awssdk:bom`. Without one, `KmsAsyncClient.builder().build()` fails with "Unable to
load an HTTP implementation". There is no Spring Boot auto-configuration for it (as in .NET, whose
dependency-injection package doesn't wire AWS either): declare the wrapper as your `KeyWrapper`
bean, and the client as a bean Spring closes.

[Wrap keys with AWS KMS](docs/how-to/use-aws-kms.md) walks through creating the key, the IAM
permissions for each role, credentials, and creating key files.
[Run the AWS KMS integration tests](docs/how-to/run-aws-kms-integration-tests.md) sets up a key of
your own for `AwsKmsIntegrationTest`, which is otherwise reported as skipped.

## Wrapping under Azure Key Vault instead

`AzureKeyVaultKeyWrapperImpl` (artifact `hkdfguard-keywrapping-azurekeyvault`) is a `KeyWrapper` over
two Azure Key Vault keys: an RSA key (2048 or 3072 bits) that wraps every DEK with RSA-OAEP-256, and
a separate EC P-256 key that signs every wrapped DEK with ES256. Use it in place of
`NativeHkdfKeyWrapperV1Impl` wherever a wrapper is taken. The private keys never leave Key Vault;
unwrapping and signing are Key Vault requests, authorized by the process's Azure credential:

```java
var wrapper = new AzureKeyVaultKeyWrapperImpl(
        "https://myvault.vault.azure.net/keys/myapp-wrap",
        "https://myvault.vault.azure.net/keys/myapp-sign",
        new DefaultAzureCredentialBuilder().build(),     // a managed identity when deployed
        "com.example.myapp");
```

- Why two keys: RSA-OAEP wrapping needs only the public key, so on its own anyone could make a
  wrapped DEK holding a key they chose. Unwrap verifies the signature first and refuses anything a
  principal allowed to `sign` didn't make. Give `sign` to the pipeline that creates key files,
  never to the application. The wrapper refuses the same key for both jobs.
- Both keys are pinned. Each wrapped DEK records only the versions of the two keys it was made
  with; the vault and key names always come from the constructor. Rotating either key in Key Vault
  needs nothing here, as long as versions in use stay enabled. Give identifiers without a version.
- The optional context is bound into the signature and must be given again, exactly, to reveal the
  DEK. It isn't secret.
- Key Vault has no "generate data key": `generateAndWrapAsync` generates the DEK in the process,
  wraps it and zeroes it. Plaintext the wrapper owns is zeroed - its copy of the key sent to be
  wrapped, and its copy of the revealed key. The SDK's request and response bodies, and the array
  inside the `UnwrapResult` (whose getter returns a copy), aren't exposed, so they can't be.
- Wrapped DEKs are byte for byte the .NET `AzureKeyVaultKeyWrapper`'s, so a key file made by either
  is read by the other, given the same keys and context.
- Failures complete the future with a `CryptographicException` naming Key Vault's error code (for
  example `Forbidden` or `KeyNotFound`) and the HTTP status, with the Azure exception as its cause;
  argument errors throw from the call. Cancelling a returned future cancels the Key Vault request in
  flight. A failed unwrap zeroes the caller's buffer.
- Key files are read through `hkdfguard-securefile`, by the same rules as for AWS KMS. A wrapped DEK
  under RSA-2048 is 359 bytes, and under RSA-3072 487, inside `WrappedKeyLimits.MAX_BYTES`.

**Dependencies.** The module depends on `com.azure:azure-security-keyvault-keys`, at the version the
`com.azure:azure-sdk-bom` in this build's parent POM pins, but excludes the HTTP client it declares
(`azure-core-http-netty`), as the AWS module does. The wrapper builds one Key Vault client per key
version it uses, with the HTTP client azure-core finds on the class path; `azure-identity`, which most
applications add for the credential, brings `azure-core-http-netty` with it, or add
`com.azure:azure-core-http-jdk-httpclient` for the JDK's own. The longest constructor takes a
`Consumer<CryptographyClientBuilder>` for the HTTP client, retries, logging or service version.
There is no Spring Boot auto-configuration for it: declare the wrapper as your `KeyWrapper` bean.

[Wrap keys with Azure Key Vault](docs/how-to/use-azure-key-vault.md) walks through creating the keys,
the roles for each identity, credentials, and creating key files.
[Run the Azure Key Vault integration tests](docs/how-to/run-azure-key-vault-integration-tests.md)
sets up a test vault for `AzureKeyVaultIntegrationTest`, which is otherwise reported as skipped.

## Wrapping under Google Cloud KMS instead

`GoogleKmsKeyWrapperImpl` (artifact `hkdfguard-keywrapping-googlekms`) is a `KeyWrapper` over one
symmetric Google Cloud KMS key (purpose `ENCRYPT_DECRYPT`). Use it in place of
`NativeHkdfKeyWrapperV1Impl` wherever a wrapper is taken. Every call is a Cloud KMS request,
authorized by the process's Google credential through IAM and recorded in Cloud Audit Logs:

```java
// The application creates the client, keeps it open while anything uses the wrapper, and closes it.
var kms = KeyManagementServiceClient.create();          // Application Default Credentials
var wrapper = new GoogleKmsKeyWrapperImpl(kms,
        "projects/my-project/locations/us-east1/keyRings/myapp/cryptoKeys/myapp-wrap",
        "com.example.myapp");
```

- `wrapAsync` calls `Encrypt` and `unwrapAsync` calls `Decrypt`. Cloud KMS has no "generate data
  key", so `generateAndWrapAsync` generates the DEK in the process, wraps it and zeroes it.
- The key is pinned: `Decrypt` is always called against the configured key, and Cloud KMS refuses a
  ciphertext made under any other. Give the key's resource name, never a key version: `Encrypt` uses
  the primary version, and a ciphertext names the version that made it, so rotation needs nothing
  here as long as versions in use stay enabled.
- A fixed HkdfGuard label and the optional context are bound into every wrapped DEK as AAD, and must
  be presented again, exactly, to reveal it. The label stops a ciphertext the same key made for
  anything else being accepted as a DEK. Neither is secret.
- Every request and response carries a CRC32C checksum, as Google recommends, so data corrupted in
  transit is refused rather than stored or used.
- Wrapped DEKs are byte for byte the .NET `GoogleKmsKeyWrapper`'s, so a key file made by either is
  read by the other, given the same key and context. A wrapped DEK is about 113 bytes.
- Failures complete the future with a `CryptographicException` naming the gRPC status and Google's
  description (for example `PERMISSION_DENIED: Permission 'cloudkms.cryptoKeyVersions.useToDecrypt'
  denied...` or `INVALID_ARGUMENT: Decryption failed.`), with the client's `ApiException` as its
  cause; argument errors throw from the call. The client's own retries (of `UNAVAILABLE`, for
  example) happen before the future completes. Cancelling a returned future cancels the gRPC call. A
  failed unwrap zeroes the caller's buffer.
- Plaintext the wrapper can reach is zeroed: its copy of the key sent to `Encrypt` (once the call,
  retries included, has completed), and the array inside the `ByteString` `Decrypt` returns. gRPC's
  serialized request and response aren't exposed, so they can't be.
- Key files are read through `hkdfguard-securefile`, by the same rules as for AWS KMS.
- Symmetric encryption needs no secret beyond permission to use the key, so anyone allowed
  `useToEncrypt` can make a key file the application accepts. Give the application Cloud KMS
  CryptoKey Decrypter only, and the pipeline that creates key files CryptoKey Encrypter only.

**Dependencies.** The module depends on `com.google.cloud:google-cloud-kms`, at the version the
`com.google.cloud:libraries-bom` in this build's parent POM pins; import the same BOM to keep gRPC,
Protobuf and gax at the versions it was tested with. Unlike the AWS and Azure SDKs, the client has
its transport built in - gRPC over a shaded copy of Netty, which puts no Netty classes on the class
path - so there is nothing to add or exclude. That transport loads a native library of its own, so
on Java 25 grant it native access too: `--enable-native-access=ALL-UNNAMED` on the class path covers
it, and on the module path add `io.grpc.netty.shaded`. The Cloud KMS client and gax name no module,
so this module has no module descriptor either: its jar names its module,
`io.github.runsecure.hkdfguard.keywrapping.googlekms`, for an application on the module path to
require. There is no Spring Boot auto-configuration for it: declare the wrapper as your `KeyWrapper`
bean, and the client as a bean Spring closes.

[Wrap keys with Google Cloud KMS](docs/how-to/use-google-kms.md) walks through creating the key, the
roles for each identity, credentials, and creating key files.
[Run the Google Cloud KMS integration tests](docs/how-to/run-google-kms-integration-tests.md) sets up
a key of your own for `GoogleKmsIntegrationTest`, which is otherwise reported as skipped.

## Wrapping under HashiCorp Vault transit instead

`HashiCorpVaultTransitKeyWrapperImpl` (artifact `hkdfguard-keywrapping-hashicorpvault`) is a
`KeyWrapper` over one key in a HashiCorp Vault transit secrets engine. Use it in place of
`NativeHkdfKeyWrapperV1Impl` wherever a wrapper is taken. The key never leaves Vault; every call is
a request to Vault's HTTP API, authorized by the token's policy and recorded in Vault's audit log:

```java
var token = new StaticVaultTokenSource(System.getenv("VAULT_TOKEN"));   // or your own VaultTokenSource
var wrapper = new HashiCorpVaultTransitKeyWrapperImpl(
        URI.create("https://vault.example.com:8200"),
        "myapp-kek",
        token,
        "com.example.myapp");
```

- `wrapAsync` calls `transit/encrypt/{key}` and `unwrapAsync` calls `transit/decrypt/{key}`.
  Without a context, `generateAndWrapAsync` calls `transit/datakey/wrapped/{key}` with
  `{"bits":256}`, so the plaintext DEK never leaves Vault; with one (which `datakey/wrapped` would
  ignore) it generates the DEK in the process, wraps it with `encrypt` and zeroes it.
- The key is pinned by its path, and a ciphertext carries only its key version, so a key file
  wrapped under another key is refused. Vault's key rotation keeps the name: key files keep revealing
  while their version is at or above the key's `min_decryption_version`. Use a non-derived AEAD key,
  such as the default `aes256-gcm96`.
- The optional context is bound into every wrapped DEK as Vault's `associated_data`, and must be
  given again, exactly, to reveal it. An answer whose warnings say Vault ignored a parameter (a Vault
  too old for `associated_data`) is refused, so a context is never silently dropped. It isn't
  secret.
- A wrapped DEK is Vault's ciphertext as it returns it, `vault:v{n}:{base64}`, in ASCII, byte for
  byte the .NET `HashiCorpVaultTransitKeyWrapper`'s, so a key file made by either is read by the
  other, given the same key and context. It is about 89 bytes.
- The token comes from a `VaultTokenSource`, which copies it into a `char[]` the wrapper owns and
  zeroes; logging in and renewing are the source's job. `StaticVaultTokenSource` holds one you
  already have.
- The address must be https, except on loopback. The wrapper's own `HttpClient` follows no
  redirects, and a supplied one that does is refused unless `allowRedirects` is set. A request that
  gets no answer, loses its connection, times out, or is answered 429 or a 5xx other than 501 is
  retried (3-10 times, 200 ms doubling, plus jitter); options set the mount, a Vault Enterprise
  namespace, the per-attempt timeout and an `HttpClient` trusting a private CA.
- Failures complete the future with a `CryptographicException` naming Vault's status and errors
  (for example `Vault answered 403 Forbidden: permission denied`), with a `VaultRequestException`
  (or, when Vault couldn't be reached, the `IOException`) as its cause; argument errors throw from
  the call. Each call runs on a virtual thread of its own; cancelling the returned future abandons
  the request. A failed unwrap zeroes the caller's buffer.
- No DEK ever becomes a `String`: the `encrypt` request body is sent from an array the wrapper
  owns, through a body publisher that doesn't copy it, Vault's answer is read straight off the
  response stream into another and parsed by hand, and every one is zeroed. The token's header
  value is the one copy that can't be: `java.net.http` takes a header only as a `String`. Below
  `java.net.http`'s API, its own buffers (TLS, HTTP/2 framing, socket reads and writes) can't be
  reached either.
- Key files are read through `hkdfguard-securefile`, by the same rules as for AWS KMS.

**Dependencies.** None beyond the JDK and HkdfGuard's own modules: HashiCorp publishes no Java SDK,
and the community driver decodes every answer into `String`s, so the wrapper calls Vault's HTTP API
through `java.net.http`, as the Vault cache does. The module has a descriptor,
`io.github.runsecure.hkdfguard.keywrapping.hashicorpvault`. Close the wrapper to release its
connections. There is no Spring Boot auto-configuration for it: declare the wrapper as your
`KeyWrapper` bean.

[Wrap keys with HashiCorp Vault transit](docs/how-to/use-hashicorp-vault-transit.md) walks through
creating the key, the policy for each role, the token, and creating key files.
[Run the HashiCorp Vault transit integration tests](docs/how-to/run-hashicorp-vault-transit-integration-tests.md)
sets up a dev server for `HashiCorpVaultTransitIntegrationTest`, which is otherwise reported as
skipped.

## Caching secrets from a secret store

Four caches read secrets from a remote store on demand: `AwsSecretsManagerSecretCacheImpl`,
`AzureKeyVaultSecretCacheImpl`, `GoogleSecretManagerSecretCacheImpl` and
`HashiCorpVaultSecretCacheImpl`. Each is a `ProtectedReadOnlyCache`. Nothing is fetched up front:
the first `decrypt` or `findMaxDecryptedLength` for a name reads that one secret, encrypts it under
the ring's current key bound to its name, and caches only the ciphertext; later lookups never call
the store. None of them ever lists secrets, so the application needs only read access to the
secrets it uses. A cached value isn't refreshed: a new secret version is picked up by a new cache.

A secret that doesn't exist, or is empty, returns 0 and is looked up again next time; any other
failure (access denied, the store unreachable) throws the SDK's exception. A name the store can't
hold, such as the configuration path `ConnectionStrings:Admin`, returns 0 without a call, so a
cache can go last in a `ProtectedCacheCollectionImpl` behind other sources.

**A secret never becomes a `String`.** Each cache takes the value out below the SDK, before the
SDK can parse it into one: the AWS and Azure caches read the raw response body into an array of
their own, hand the value to the cache as bytes (`SecretJsonBody`), and give the SDK the body with
the value blanked; the Vault cache reads its response the same way, with no SDK above it; the
Google cache reads gRPC's message into an array of its own instead of gRPC's reused thread-local
buffer, and zeroes it and the payload once the payload is encrypted. Every array that held a value
is zeroed. Out of reach are the HTTP stack's own buffers (TLS decryption, socket reads, Netty's
pools) and, as everywhere on the JVM, copies a compacting collector left behind.

### AWS Secrets Manager

```java
// The application builds, configures and closes the client, as for AWS KMS.
var client = SecretsManagerAsyncClient.create();
var secrets = new AwsSecretsManagerSecretCacheImpl(client, ring, null);

var buffer = new char[256];
int written = secrets.decrypt("prod/Db-Password", buffer); // 0 if the secret doesn't exist
```

`GetSecretValue` reads the secret's `AWSCURRENT` version; the principal needs only
`secretsmanager:GetSecretValue` (plus `kms:Decrypt` on a customer managed key that encrypts it).
Names match exactly, as Secrets Manager's do: anything but 1-512 ASCII letters, digits and
`/_+=.@-` returns 0 without a call, so look secrets up by name, not ARN. A `SecretString` is cached
as its UTF-8 bytes and a `SecretBinary` as its bytes. The capture is attached to each request as a
per-request plugin, so the application's client is left as it is and can be shared.

### Azure Key Vault

```java
var builder = new SecretClientBuilder()
        .vaultUrl("https://myvault.vault.azure.net/")
        .credential(new DefaultAzureCredentialBuilder().build());
var secrets = new AzureKeyVaultSecretCacheImpl(builder, ring);
```

`GetSecret` reads the secret's current version; the application needs only the **Key Vault
Secrets User** role (`get`), never `list`. Names are 1-127 ASCII letters, digits and hyphens,
compared ignoring case as Key Vault compares them. The cache builds its own `SecretClient` from the
builder you pass - set the HTTP client, retry options and so on there - and changes that builder:
it adds its capture policy, clears any `HttpPipeline` set on it (which would replace that policy),
and sets HTTP log options that never log bodies (the environment's level, with `BODY` becoming
`NONE` and `BODY_AND_HEADERS` becoming `HEADERS`), since the logging policy sees the response before
the capture does.

### Google Cloud Secret Manager

```java
try (var secrets = GoogleSecretManagerSecretCacheImpl.create("my-project", ring, null)) { // ADC
    int written = secrets.decrypt("Db-Password", buffer);
}
```

`AccessSecretVersion` reads the secret's `latest` version; the application needs only the
**Secret Manager Secret Accessor** role. Secret IDs match exactly: anything but 1-255 ASCII
letters, digits, hyphens and underscores returns 0 without a call. A payload whose CRC32C doesn't
match the checksum Google returns, or a response naming another secret, is refused with a
`CryptographicException`. For your own credentials or endpoint, pass `SecretManagerServiceSettings`
to the constructor: its transport must be an `InstantiatingGrpcChannelProvider` (the default),
which the cache keeps as configured and adds its interceptor to. The cache owns the client it
builds, so close it.

### HashiCorp Vault

```java
var tokenProtector = ring.createProtector(HashiCorpVaultSecretCacheImpl.TOKEN_PURPOSE);
try (var secrets = new HashiCorpVaultSecretCacheImpl(
        URI.create("https://vault.example.com:8200"),
        StaticVaultToken.protect(tokenProtector, System.getenv("VAULT_TOKEN")), // held encrypted
        tokenProtector,
        ring,
        HashiCorpVaultSecretCacheOptions.builder().mountPath("secret").build(), // KV version 2 unless set to V1
        null)) {
    int written = secrets.decrypt("myapp/db#password", buffer); // 0 if there's no such secret or key
}
```

A Vault secret holds several keys, so a name is the secret's path with the key after `#`; a name
without one reads `defaultKey` (`value` unless set). The token's policy needs only `read`.
Authentication is left to a `VaultTokenProvider`, asked on every fetch, so a provider can log in
and renew however it likes; it hands the token over encrypted by the token protector, and a fetch
given anything else fails with `IllegalStateException` without calling Vault. The token is
decrypted into a `char[]` that is zeroed, but `java.net.http` takes a header only as a `String`,
which Java can't zero: one is made for each request and dropped once it is sent. The address must
be https except on loopback, and the cache's own client follows no redirects, which would carry the
token elsewhere; a client you supply that follows redirects is refused unless `allowRedirects` is
set. A failure that isn't "not found" throws `VaultRequestException` with Vault's status and
errors, never the token. Transient failures (no answer, a timed-out attempt, 429, a 5xx other than
501) are retried `retryCount` times (3-10), backing off from `retryDelay` up to 10 seconds plus a
random 0-100 ms.

### Secrets holding several keys

Every cache reads one key of a secret holding a JSON object - an AWS key/value secret, a JSON
object kept in a Key Vault secret or Google payload, any Vault KV secret - as `secret#key`:

```java
int written = secrets.decrypt("prod/app#api-credential-21", buffer);
written = secrets.decrypt("prod/app#port", buffer);  // "5432"
written = secrets.decrypt("prod/app", buffer);       // the whole JSON text
```

The first lookup of any key fetches the secret once and caches its whole value and every key,
each encrypted on its own and bound to its own name; concurrent lookups of different keys share
that fetch. A string member is cached as its UTF-8 bytes; a number, `true` or `false` as its JSON
text; `null`, an object, an array, an empty string, or a member whose name isn't a key (1-256
printable ASCII characters other than space, `!` and `#`) is left out. A value that isn't exactly
one JSON object is cached whole only; an object naming a member twice is refused with
`InvalidSecretDataException`. Keys match exactly, even in Key Vault. A key the secret doesn't hold
returns 0 and costs a fetch each time it is asked for.

### Reading asynchronously

Every `ProtectedReadOnlyCache` also has `decryptAsync` (into a `byte[]` or `char[]`) and
`findMaxDecryptedLengthAsync`, returning `CompletableFuture`. On a secret-store cache they fetch a
missing secret without blocking the caller: through the SDK's asynchronous call for AWS and Google,
and on a virtual thread for Azure and Vault. `decrypt` blocks until the store answers.
`ProtectedCacheCollectionImpl` asks each source in turn the same way. Every other cache gets them
from the interface, where they call the synchronous members.

Synchronous and asynchronous lookups of the same uncached secret share one fetch. Cancelling a
lookup's future stops it waiting, and cancels the fetch itself only if that lookup started it; a
lookup whose fetch was cancelled by another starts a new one rather than failing.

### Another secret store

All four derive from `RemoteSecretCache` (in `hkdfguard-cache`), which owns fetching, caching,
encryption, name matching and telemetry. Another store needs only a subclass:

```java
public final class MySecretStoreCache extends RemoteSecretCache {
    private final MyClient client;

    public MySecretStoreCache(MyClient client, KeyRing ring) {
        super(ring, SecretNameMatching.EXACT, null);
        this.client = client;
    }

    @Override
    protected boolean isValidName(String name) {
        return name.chars().allMatch(Character::isLetterOrDigit);
    }

    // Hand the value to the sink, or return without doing so if the secret doesn't exist.
    @Override
    protected void fetch(String name, SecretValueSink value) {
        var secret = client.get(name); // bytes, never a String
        if (secret != null)
            value.setBytes(secret);    // zeroed once encrypted
    }
}
```

Override `fetchAsync` too if the client is asynchronous; without it, `decryptAsync` runs `fetch`
on a virtual thread.

## Building

```
./mvnw verify        # mvnw.cmd on Windows
```

## Native integration tests

The native tests make real calls into this platform's KMS library: `NativeKeyWrappingIntegrationTest`
and `NativeKeyFileTest` in hkdfguard-keywrapping-v1, `NativeEndToEndTest` and
`NativeKeyFileRingTest` in hkdfguard-dataencryptionkey, and `NativeEndToEndCacheTest` in
hkdfguard-cache. The key-file refusals that need no KEK run wherever the Windows library is
installed. Each platform also has its own suite, the same cases as the .NET, Go, Python and Node
ports; every test that can't run here is reported as skipped, never as passed:

| Platform | Suite (hkdfguard-keywrapping-v1, `interop` package) | Gating |
|---|---|---|
| Linux | `LinuxNativeLibraryLoaderSystemTest`: the loader against this machine's filesystem and dynamic linker | Linux only; the installed-library tests also need the libhkdfguard1 package |
| Linux | `LinuxNativeIntegrationTest`: exact status codes, the library's own input checks, zeroing on failure, and the hkdfguard CLI deployment path | Linux, the libhkdfguard1 package and `HKDFGUARD_TEST_SERVICE`; some tests also need `HKDFGUARD_TEST_SERVICE_OTHER`, `tpm.require_pinned_names = true` in `/etc/hkdfguard/policy.toml`, or `/usr/bin/hkdfguard` |
| macOS | `MacOsNativeIntegrationTest`: the installed `libhkdfguard.dylib` passes location and signature checks, the provisioning tool and unsigned or user-owned files are refused, and `hkdfguard status` agrees with the test service resolution | macOS only; most tests also need the library, or `hkdfguard` beside it, installed |
| Windows | `WindowsNativeLibraryLoaderTest` (its installed-library tests), `NativeKeyFileTest`, `NativeKeyWrappingIntegrationTest`, `NativeEndToEndTest`, `NativeEndToEndCacheTest`, `NativeProcessHardeningTest` | Windows; `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll` installed; a provisioned KEK for the round trips |

On Linux the test KEKs come from `scripts/provision-linux-test-key.sh`, run once with `sudo` on a
TPM host from the account that runs the tests (`--remove` removes the policy it wrote). It provisions `com.hkdfguard.integration.test.221` and sets the pinned-names allowlist; Linux has
no non-prompting way to ask whether a KEK exists, so name it explicitly. The cross-service
isolation tests use a service that is never provisioned, unless `HKDFGUARD_TEST_SERVICE_OTHER`
names a second real KEK:

```bash
HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 \
./mvnw verify
```

The Linux library refuses a key file below any group- or world-writable directory, sticky or not
(`/tmp`, `/var/tmp`, `/dev/shm`), so the tests write key files to a private 0700 directory under
`$XDG_RUNTIME_DIR` when that is trusted, else under `~/.cache/hkdfguard-tests`, and skip the
key-file tests (saying why) when neither is (`NativeTestEnvironment.createTempDirectory`, in
hkdfguard-test-support).

On macOS, with `HKDFGUARD_TEST_SERVICE` unset, the tests use `com.hkdfguard.integration.test.221` when
the installed `hkdfguard status` reports it present, and are skipped when it reports it
absent. The first call from the test JVM can raise a keychain dialog (click "Always Allow"); it is
made with a 60-second deadline, so a dialog nobody answers fails the run instead of hanging it. Every
platform's library refuses to create a KEK while wrapping or unwrapping, so these tests run only
against a service provisioned beforehand. Without one they are reported as skipped, never as
passed. Once a service is chosen, a missing or failing library is a test failure.

**Windows.** Install the HkdfGuard native package, then provision the test KEK
`com.hkdfguard.integration.test.221` once, from an elevated PowerShell at the repository root:

```powershell
./scripts/provision-windows-test-key.ps1
```

The script runs the installed `hkdfguard.exe provision`, after checking it is the signed
tool from its fixed install location (the same publisher, pinned root and Artifact Signing profile
the library's own loader requires). It is safe to re-run: an existing KEK is re-verified, not
replaced. It also retires the legacy per-platform test KEK `com.hkdfguard.native.windows.test`,
which no test uses any more, after asking (`-KeepLegacyKey` keeps it). `-Remove` retires the test
KEKs instead, each only after `hkdfguard status` confirms its fingerprint; `-WhatIf` shows what
either would delete. Afterwards the tests find the KEK on their own:

```powershell
.\mvnw.cmd verify
```

If the KEK exists but your account may not use it, add the account to the `HkdfGuardUsers` group
(then sign out and in), or run the tests elevated.

**Any platform.** Name a provisioned service in `HKDFGUARD_TEST_SERVICE`; it always wins over the
Windows default, and setting it means the native tests must run. Set `HKDFGUARD_TEST_SERVICE_OTHER`
to a second provisioned service to test cross-service isolation against a different KEK (otherwise
that test uses a service that is never provisioned):

```bash
hkdfguard provision --service-name hkdfguard.integrationtest   # elevated on Windows
HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest ./mvnw verify
```

The tests only ever use a provisioned KEK: they never create or delete one.

**Process hardening.** `NativeProcessHardeningTest`'s Windows and Linux tests harden the test JVM
itself, so they run only with `HKDFGUARD_TEST_PROCESS_HARDENING=1` (and the native library
installed). Run them on their own, each in its own JVM, since the plain and strict forms can't be
undone:

```bash
export HKDFGUARD_TEST_PROCESS_HARDENING=1
./mvnw -pl hkdfguard-keywrapping-v1 -am test -Dsurefire.failIfNoSpecifiedTests=false -Dtest='NativeProcessHardeningTest#apply_OnWindows_ClosesTheProcessToItsOwnAccount'
./mvnw -pl hkdfguard-keywrapping-v1 -am test -Dsurefire.failIfNoSpecifiedTests=false -Dtest='NativeProcessHardeningTest#apply_OnWindows_WithRequireProtectedSignature_Succeeds'
./mvnw -pl hkdfguard-keywrapping-v1 -am test -Dsurefire.failIfNoSpecifiedTests=false -Dtest='NativeProcessHardeningTest#apply_OnLinux_*'
```
