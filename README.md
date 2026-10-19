# hkdfguard-java

HkdfGuard Key Wrapping and Secret Protection library for Java - the Java port of
[hkdfguard-dotnet](https://github.com/runsecure/hkdfguard-dotnet). Values encrypted by either
library decrypt with the other: the wire format, AAD rules, AES-GCM layout, span/metric names and
log event ids are identical.

Requires **Java 21** or later (the previous LTS) for every module except `hkdfguard-keywrapping-v1`,
which requires **Java 25** (the current LTS). Cryptography is BouncyCastle; telemetry is the
OpenTelemetry API; logging is SLF4J; native KMS calls use the Java FFM API, which is final only from
Java 22 - hence the key wrapper's higher minimum. On Java 21, use the library with a `KeyWrapper` of
your own (a cloud KMS, say) in place of the native one. Building the library needs JDK 25; CI also
runs the Java 21 modules' tests on a Java 21 runtime.

## Modules

| Artifact (`io.github.runsecure`)      | .NET assembly                        | Contents |
|---------------------------------------|--------------------------------------|----------|
| `hkdfguard-diagnostics`               | HkdfGuard.Diagnostics                | `HkdfGuardTelemetry`, span/attribute/event/metric names, `HkdfGuardLog` |
| `hkdfguard-abstractions`              | HkdfGuard.Abstractions               | `CryptoProvider`, `KeyWrapper`, `KeyRing`, `DataProtector`, ... ; `ProtectedCacheBase`, `ServiceNames`, `ProtectedConfigurationPurpose` |
| `hkdfguard-cryptoprovider-aesgcm256`  | HkdfGuard.CryptoProvider.AesGcm256   | `AesGcmCryptoProviderImpl`, `AesGcmCryptoProviderFactoryImpl`, `AesGcmPipelineDataProtectorImpl` |
| `hkdfguard-keywrapping-v1`            | HkdfGuard.KeyWrapping.V1             | `NativeHkdfKeyWrapperV1Impl` over the native KMS library, `NativeProcessHardening` (Java 25+) |
| `hkdfguard-dataencryptionkey`         | HkdfGuard.DataEncryptionKey          | `KeyRingImpl`, `KeyRingBuilder`, `DataEncryptionKeyImpl`, `DefaultFormatProviderImpl` |
| `hkdfguard-cache`                     | HkdfGuard.Cache                      | `ProtectedCacheImpl`, `ProtectedCacheCollectionImpl` |
| `hkdfguard-options`                   | HkdfGuard.Options                    | `HkdfGuardOptions`, `KeyFileOptions`, `OptionsValidationException` |
| `hkdfguard-spring-boot-starter`       | HkdfGuard.DependencyInjection, HkdfGuard.EncryptedConfiguration | Spring Boot 4 auto-configuration of the key ring, `ProtectedEnvironment`, and an Actuator health indicator |

Naming: interfaces drop the .NET `I` prefix (`ICryptoProvider` -> `CryptoProvider`), and the classes
implementing them end in `Impl`.
Plain data classes that implement no interface (`HkdfGuardOptions`, `KeyFileOptions`) keep their
.NET names.

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

- **Async** is `CompletableFuture`; there is no `CancellationToken`. Argument errors throw from the
  call itself; failures revealing a key complete the future exceptionally. Background refresh and
  rotation run on virtual threads.
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
  off-heap and zeroed before release.
- **Logging**: a null logger means the class's own SLF4J logger. .NET's Critical level is ERROR
  with the `CRITICAL` marker; the event id travels as the `hkdfguard.event_id` key-value.
- **Telemetry** goes to `GlobalOpenTelemetry` (read without latching a no-op), or to the instance
  given to `HkdfGuardTelemetry.setOpenTelemetry`.

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
  It never calls the KMS, and its only detail is `currentVersion`. Turn it off with
  `management.health.hkdfguard.enabled=false`.

## Native access

`hkdfguard-keywrapping-v1` calls the native KMS library through FFM, a restricted API. Run with
`--enable-native-access=io.github.runsecure.hkdfguard.keywrapping.v1` (module path) or
`--enable-native-access=ALL-UNNAMED` (class path). The native library is installed separately and
loaded only from its verified location, exactly as in .NET (path ACLs, Authenticode signer/root/EKU
and PE checks on Windows; ownership, code signature and dyld checks on macOS; ownership, a
SHA-256 release pin, the dynamic linker's environment and every loaded dependency on Linux).

Installed locations:

| Platform | Native library                                              | Command-line tool                        |
|----------|-------------------------------------------------------------|------------------------------------------|
| Windows  | `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll`                  | `%ProgramFiles%\HkdfGuard\v1\hkdfguard.exe` |
| Linux    | `/usr/lib/<multiarch>/libhkdfguard.so.1` or `/usr/lib64/libhkdfguard.so.1` (the `libhkdfguard1` package; `hkdfguard-libs` on RPM distributions); x64 and arm64 | `/usr/bin/hkdfguard` |
| macOS    | `/Library/Application Support/HkdfGuard/v1/libhkdfguard_v1.dylib` or `~/.hkdfguard/v1/` | `hkdfguard-v1-initialize`  |

On **Linux**, `LinuxNativeLibraryLoader` uses the package's file in the Debian multiarch directory
(`/usr/lib/x86_64-linux-gnu` or `/usr/lib/aarch64-linux-gnu`) if it is there, otherwise the one in
`/usr/lib64`. Only "nothing is there" moves on; a location that can't be examined is refused.
Before loading, it requires all of the following:
- Every directory on the path, every symbolic link followed, and the file itself are owned by root,
  and no directory or file is writable by its group or by others. Links are followed one component
  at a time and each target is checked where it lies, so `/lib -> usr/lib` passes and a link into a
  user's directory does not.
- The file's SHA-256 is a release this version of `hkdfguard-keywrapping-v1` lists (the same list
  as the .NET package's). Linux has no platform code signature, so this pin is the content check.
  Each distribution and architecture has its own build, and a release that isn't listed is refused
  until the library lists it.
- The dynamic linker's environment can't substitute anything. The library is loaded by its
  verified absolute path, which is never searched for, but its dependencies are found by name - and
  `libtss2-esys` receives every ECDH shared secret. So every `LD_LIBRARY_PATH` directory, and every
  path-named `LD_PRELOAD` or `LD_AUDIT` object, must pass the same path checks, and none may be
  relative, empty (the working directory) or use `$ORIGIN`-style tokens. Both the environment the
  process started with (`/proc/self/environ`) and the current one are checked.

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
could write or replace. Each refusal is an `IOException` naming the path and the native status:
`NoSuchFileException` (-32), `AccessDeniedException` (-33 access denied, -39 untrusted location),
`InvalidKeyFileException` (-35 too short, -36 too long, -37 plaintext key, -38 malformed), or a
plain `IOException` (-34 and anything else). Other key wrappers read with ordinary file I/O
(`WrappedKeyFile.read`), refusing only an empty file or one over `WrappedKeyLimits.MAX_BYTES`.

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
| -16 | KEK_FINGERPRINT_MISMATCH | | -98 | MAC_KEYCHAIN_WRITE_FAILED |
| -17 | KEK_NOT_FOUND | | -99 | MAC_KEK_VERIFICATION_FAILED |
| -18 | KEK_ACCESS_DENIED | | -100 | MAC_KEYCHAIN_READ_FAILED |
| -19 | KEK_INVALID | | | |

Every other negative code (-7, -13..-15, -21..-31, -40..-63, ...) is reserved.

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
| macOS | `MacOsNativeIntegrationTest`: the installed `libhkdfguard_v1.dylib` passes location and signature checks, the provisioning tool and unsigned or user-owned files are refused, and `hkdfguard-v1-initialize status` agrees with the test service resolution | macOS only; most tests also need the library, or `hkdfguard-v1-initialize` beside it, installed |
| Windows | `WindowsNativeLibraryLoaderTest` (its installed-library tests), `NativeKeyFileTest`, `NativeKeyWrappingIntegrationTest`, `NativeEndToEndTest`, `NativeEndToEndCacheTest`, `NativeProcessHardeningTest` | Windows; `%ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll` installed; a provisioned KEK for the round trips |

On Linux the test KEKs come from the .NET port's `scripts/provision-linux-test-key.sh` on a TPM
host, which provisions `com.hkdfguard.native.linux.test` and `com.hkdfguard.native.linux.test.other`
and sets the pinned-names allowlist; Linux has no non-prompting way to ask whether a KEK exists, so
name them explicitly:

```bash
HKDFGUARD_TEST_SERVICE=com.hkdfguard.native.linux.test \
HKDFGUARD_TEST_SERVICE_OTHER=com.hkdfguard.native.linux.test.other \
./mvnw verify
```

On macOS, with `HKDFGUARD_TEST_SERVICE` unset, the tests use `com.hkdfguard.native.macos.test` when
the installed `hkdfguard-v1-initialize status` reports it present, and are skipped when it reports it
absent. Every
platform's library refuses to create a KEK while wrapping or unwrapping, so these tests run only
against a service provisioned beforehand. Without one they are reported as skipped, never as
passed. Once a service is chosen, a missing or failing library is a test failure.

**Windows.** Install the HkdfGuard native package, then provision the test KEK
`com.hkdfguard.native.windows.test` once, from an elevated PowerShell at the repository root:

```powershell
./scripts/provision-windows-test-key.ps1
```

The script runs the installed `hkdfguard.exe provision`, after checking it is the signed
tool from its fixed install location (the same publisher, pinned root and Artifact Signing profile
the library's own loader requires). It is safe to re-run: an existing KEK is re-verified, not
replaced. Afterwards the tests find the KEK on their own:

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
hkdfguard provision --service-name hkdfguard.integrationtest   # elevated on Windows (hkdfguard-v1-initialize on macOS)
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
