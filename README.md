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
| `hkdfguard-keywrapping-v1`            | HkdfGuard.KeyWrapping.V1             | `NativeHkdfKeyWrapperV1Impl` over the native KMS library (Java 25+) |
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
and PE checks on Windows; ownership, code signature and dyld checks on macOS).

## Building

```
./mvnw verify        # mvnw.cmd on Windows
```

## Native integration tests

The native tests make real calls into this platform's KMS library: `NativeKeyWrappingIntegrationTest`
in hkdfguard-keywrapping-v1 and `NativeEndToEndTest` in hkdfguard-dataencryptionkey. Every
platform's library refuses to create a KEK while wrapping or unwrapping, so these tests run only
against a service provisioned beforehand. Without one they are reported as skipped, never as
passed. Once a service is chosen, a missing or failing library is a test failure.

**Windows.** Install the HkdfGuard native package, then provision the test KEK
`com.hkdfguard.native.windows.test` once, from an elevated PowerShell at the repository root:

```powershell
./scripts/provision-windows-test-key.ps1
```

The script runs the installed `hkdfguard-v1-initialize provision`, after checking it is the signed
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
hkdfguard-v1-initialize provision --service-name hkdfguard.integrationtest   # elevated on Windows
HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest ./mvnw verify
```

The tests only ever use a provisioned KEK: they never create or delete one.
