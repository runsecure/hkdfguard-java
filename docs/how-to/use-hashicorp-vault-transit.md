# Wrap keys with HashiCorp Vault transit

This page sets up a key in a HashiCorp Vault transit secrets engine as HkdfGuard's KEK and uses it
from Java with `HashiCorpVaultTransitKeyWrapperImpl`, in place of the native TPM, Secure Enclave or
Platform Crypto Provider KEK.

Use it when your applications already authenticate to Vault, or run somewhere a cloud KMS isn't
available, and you want key access controlled by Vault policy and recorded in Vault's audit log
rather than tied to one machine's TPM.

To run the transit integration tests against a Vault dev server, see
[Run the HashiCorp Vault transit integration tests](run-hashicorp-vault-transit-integration-tests.md).

## How it differs from the native wrapper

| | Native (`NativeHkdfKeyWrapperV1Impl`) | Vault transit (`HashiCorpVaultTransitKeyWrapperImpl`) |
|---|---|---|
| KEK | A P-256 key in the TPM, Secure Enclave or Platform Crypto Provider | An `aes256-gcm96` transit key |
| Identified by | A service name | Vault's address and the key's name |
| Who may wrap and unwrap | Local accounts and groups the native library allows | Tokens whose policy grants `update` on the key's `encrypt`, `decrypt` and `datakey/wrapped` paths |
| Each call | Local | A request to Vault's HTTP API, recorded in Vault's audit log |
| Key file reads | Through the native library, which refuses files another account could have replaced | The same rules, checked in Java by `hkdfguard-securefile`; who else is trusted is set with `KeyFileTrust` |
| Install | The native package | Nothing beyond the artifact: it talks to Vault's HTTP API through the JDK's `java.net.http` |

Wrapped DEKs aren't interchangeable. A key file wrapped by one wrapper can't be unwrapped by the
other, so each DEK belongs to the wrapper that created it. A transit-wrapped DEK is Vault's
ciphertext as it returns it, `vault:v1:...`, about 89 bytes of ASCII. It is byte for byte what the
.NET `HashiCorpVaultTransitKeyWrapper` and the Go port produce, so any of them reads the others' key
files, given the same key and context.

HashiCorp publishes no Java SDK, and the community Vault driver decodes every answer into
`String`s, which a revealed DEK must never become. So the wrapper calls Vault's HTTP API itself and
reads its answers byte by byte; it has no dependency beyond the JDK and HkdfGuard's own modules.

## 1. Create the transit key

As a Vault operator, enable the engine (once) and create the key:

```bash
vault secrets enable transit
vault write -f transit/keys/myapp-kek type=aes256-gcm96
```

| Setting | Choose | Why |
|---|---|---|
| `type` | `aes256-gcm96` (the default), `aes128-gcm96` or `chacha20-poly1305` | The wrapper needs an AEAD key for its context (associated data) |
| `derived` | `false` (the default) | A derived key needs a `context` on every request, which the wrapper doesn't send. Worse, a key that *isn't* derived silently ignores one, so the wrapper binds its context as `associated_data` instead |
| `exportable` | `false` (the default) | Nothing here needs the key material out of Vault |
| `deletion_allowed` | `false` (the default) | Deleting the key makes every DEK wrapped under it unreadable, for good |

Rotate it with `vault write -f transit/keys/myapp-kek/rotate`. New DEKs are wrapped under the latest
version; existing key files keep revealing as long as their version is at or above the key's
`min_decryption_version`, so don't raise that until every key file is rewrapped.

## 2. Grant each role only what it calls

Give `update`, and never `create`, on exactly the paths each role uses. `transit/encrypt/{name}`
creates a key that doesn't exist yet when the token has `create`, so with it a mistyped key name
would quietly wrap DEKs under a brand-new key.

A release pipeline that creates key files:

```hcl
path "transit/encrypt/myapp-kek"         { capabilities = ["update"] }
path "transit/datakey/wrapped/myapp-kek" { capabilities = ["update"] }
```

The application, which only reads existing key files:

```hcl
path "transit/decrypt/myapp-kek" { capabilities = ["update"] }
```

Add `transit/encrypt/myapp-kek` (and `transit/datakey/wrapped/myapp-kek`) to the application only
if it generates ephemeral keys at startup.

```bash
vault policy write myapp-kek-pipeline pipeline.hcl
vault policy write myapp-kek-app app.hcl
```

Then bind each policy to the auth method its role logs in with (AppRole, Kubernetes, a certificate,
a cloud IAM role).

## 3. Give the process a token

Every request is made with a token from a `VaultTokenSource`. Logging in, renewing and replacing
the token is the source's job, so any auth method can sit behind the wrapper. The source copies the
token into a `char[]` the wrapper owns and zeroes once the call is done, rather than handing it over
as a `String`.

`StaticVaultTokenSource` holds a token you already have, such as one a Vault Agent wrote to a sink
file. Nothing renews it, so once it expires every request fails with 403. Close it to zero its copy:

```java
import io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.StaticVaultTokenSource;

var token = new StaticVaultTokenSource(System.getenv("VAULT_TOKEN"));
```

It takes any `CharSequence`: to keep the token out of `String` altogether, read it into a `char[]`,
pass `CharBuffer.wrap(chars)`, and clear the array once the constructor returns.

For a long-running service, prefer a Vault Agent on loopback with `use_auto_auth_token`, which
renews the token itself, or implement `VaultTokenSource` over your auth method:

```java
VaultTokenSource tokens = destination -> myLogin.currentTokenAsync().thenApply(current -> {
    current.getChars(0, current.length(), destination, 0);   // or copy from a char[] you hold
    return current.length();
});
```

The wrapper waits for the source's future for at most its timeout, and cancels it after that. Write
to `destination` only before completing the future. A source's failure fails the call as it is, and
isn't retried.

> **Note:** this is not the cache's `VaultTokenProvider`. That one hands over a token protected by
> the key ring; a key wrapper runs before there is a key ring, so it can't.

## 4. Create the wrapper

Add the artifact:

```xml
<dependency>
  <groupId>io.github.runsecure</groupId>
  <artifactId>hkdfguard-keywrapping-hashicorpvault</artifactId>
  <version>1.0.0</version>
</dependency>
```

> **TODO (maintainer):** confirm the version once the artifact is published.

The module needs Java 25, like `hkdfguard-securefile`, which checks key files with system calls made
through the FFM API. Grant it native access: `--enable-native-access=ALL-UNNAMED` on the class path,
or `--enable-native-access=io.github.runsecure.hkdfguard.securefile,io.github.runsecure.hkdfguard.platform`
on the module path, where this is the module `io.github.runsecure.hkdfguard.keywrapping.hashicorpvault`.

```java
import io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.HashiCorpVaultTransitKeyWrapperImpl;
import java.net.URI;

var wrapper = new HashiCorpVaultTransitKeyWrapperImpl(
        URI.create("https://vault.example.com:8200"),
        "myapp-kek",
        token,
        "com.example.myapp");
```

- **The address must be https**, except on a loopback address (a local Vault Agent or dev server):
  every request carries a token, and wrap and unwrap carry plaintext DEKs. A path is kept as a
  prefix, for Vault behind a reverse proxy. The wrapper's own `HttpClient` follows no redirects,
  which would carry the token elsewhere; a client you supply in the options that does is refused
  unless you set `allowRedirects`.
- **The context** is bound into every wrapped DEK as Vault's `associated_data` and must be given
  again, exactly, to reveal it. Use the same value on every wrapper that handles one application's
  key files. It isn't a secret and must not hold one.
- **With a context, `generateAndWrapAsync` generates the DEK in your process** and wraps it with
  `encrypt`, because `datakey/wrapped` ignores `associated_data`. Without one, Vault generates it
  and returns it wrapped only, so the plaintext DEK never leaves Vault on that call. Choose a context
  for the binding, or none for generation in Vault.
- **Old Vaults are refused, not trusted.** If Vault answers that it ignored a parameter, as one
  too old for `associated_data` does, the call fails rather than return a DEK bound to no context.
- **Each call runs on a virtual thread of its own** and returns a `CompletableFuture` at once.
  Cancelling the future abandons the request.
- **Close the wrapper** to release its connections, but only once nothing uses it, including a
  key ring's background refresh. It doesn't close the token source or a client you supply.

Options (`HashiCorpVaultTransitKeyWrapperOptions`) set a mount other than `transit`, a Vault
Enterprise namespace, the per-attempt timeout (30 seconds, covering the token and the whole
response), and retries: a request that gets no answer, loses its connection, times out, or is
answered 429 or a 5xx other than 501 is retried 3 times by default, waiting 200 ms and doubling,
plus up to 100 ms of jitter. To trust a private CA, supply an `HttpClient` with an `SSLContext` that
trusts it and `followRedirects(HttpClient.Redirect.NEVER)`:

```java
import io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.HashiCorpVaultTransitKeyWrapperOptions;
import java.net.http.HttpClient;

var client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .sslContext(sslContextTrustingYourCa)
        .build();
var options = HashiCorpVaultTransitKeyWrapperOptions.builder()
        .mountPath("transit/team-a")
        .namespace("team-a/prod")
        .httpClient(client)
        .build();
var wrapper = new HashiCorpVaultTransitKeyWrapperImpl(address, "myapp-kek", token, "com.example.myapp", null, options);
```

### What is zeroed, and what can't be

The wrapper never turns a DEK into a `String`. The `encrypt` request body, which holds the DEK in
base64, is built in an array the wrapper owns, handed to `java.net.http` by a body publisher that
wraps that array rather than copying it, and zeroed once every attempt is done. Vault's answer is
read straight off the response stream into another array of its own, the value is taken out of it
by hand (no JSON library, no `String`), and the decoded DEK goes through a third; all are zeroed.
The token's `char[]` is zeroed too.

What can't be zeroed:

- **The token's header value.** `java.net.http` takes a header only as a `String`, and a Java
  `String` can't be zeroed. Each request's token becomes one `String`, made for that request alone
  and referenced by nothing once it has been sent; it stays in memory until the garbage collector
  reuses it. The cache module does the same, for the same reason.
- **Below `java.net.http`'s API**: its header buffers, its response stream's buffers, HTTP/2
  framing, TLS encryption and decryption, and the socket's reads and writes.
- **Old copies a compacting garbage collector left behind.** Java has no pinned arrays; zeroing
  erases the live copy, as `ArrayUtility` explains.

## 5. Build a key ring with an ephemeral key

An ephemeral key is generated at startup and never written anywhere:

```java
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;

try (var ring = new KeyRingBuilder()
        .withServiceName("com.example.myapp")
        .withKeyWrapper(wrapper)
        .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
        .withKeyRefreshInterval(300)
        .withEphemeralKey(1)
        .buildAsync()
        .join()) {
    var protector = ring.createProtector("customer-notes");
    String encrypted = protector.encrypt("The launch code is 0000");
}
```

Everything encrypted under an ephemeral key is lost when the process exits. Data you store needs a
key file.

## 6. Create a key file

The release pipeline creates key files with the wrapper itself, logged in as the pipeline role from
step 2:

```java
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
int length = wrapper.generateAndWrapAsync(wrapped).join();
Files.write(Path.of("C:\\HkdfGuardKeys\\myapp\\v1.key"), Arrays.copyOf(wrapped, length));
```

To wrap a key the pipeline already holds, such as an `AesGcmPipelineDataProtectorImpl`'s, call
`wrapAsync` with it and zero your copy afterwards, as
[Wrap keys with AWS KMS](use-aws-kms.md#6-create-a-key-file) shows. `wrapAsync` takes 1-256 bytes.

Key files are read only from where no untrusted account could have written or replaced them: anyone
who can replace a key file *and* call `encrypt` on the key could otherwise choose your application's
DEK. The rules, the folder setup and `KeyFileTrust` for a deployer account are the same as for AWS
KMS; see [Where key files can live](use-aws-kms.md#where-key-files-can-live). Pass the
`KeyFileTrust` as the wrapper's `keyFileTrust` argument.

## 7. Use the key file

```java
try (var ring = new KeyRingBuilder()
        .withServiceName("com.example.myapp")
        .withKeyWrapper(wrapper)
        .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
        .withKeyRefreshInterval(300)
        .withKeyFile(1, "C:\\HkdfGuardKeys\\myapp\\v1.key")
        .buildAsync()
        .join()) {
    // ...
}
```

`buildAsync` calls `decrypt` once per key, so the application fails to start if Vault can't be
reached or refuses the key. Each key then calls `decrypt` once per `withKeyRefreshInterval`: at 300
seconds, 8,640 requests per key per process every 30 days, each one in the audit log.

## If something goes wrong

Every Vault failure completes the future with a `CryptographicException` whose message gives
Vault's status and errors. Its `getCause()` is a `VaultRequestException` (with `statusCode()`) when
Vault answered, or the `IOException` - an `HttpTimeoutException` for a timeout - when it couldn't be
reached. A failed unwrap zeroes the caller's buffer. A token source's own failure completes the
future as it is; argument errors throw from the call.

| The message names | Cause | Fix |
|---|---|---|
| `403 Forbidden` ... `permission denied` | The token's policy doesn't grant `update` on this path, or the token is invalid or expired | Step 2's paths; renew or replace the token |
| `400 Bad Request` ... `encryption key not found` | No key by that name in this mount (or namespace) | Check the key name, `mountPath` and `namespace` |
| `400 Bad Request` ... `cipher: message authentication failed` | The key file was altered, wrapped under another key, or with a different context | Restore the file; use the key and context it was created with |
| `400 Bad Request` ... `missing 'context' for key derivation` | The key is derived | Create a key with `derived=false` and rewrap |
| `400 Bad Request` ... `disallowed by policy (too old)` | The file's key version is below `min_decryption_version` | Lower it, or rewrap the file under the current version |
| `ignored a parameter` | This Vault doesn't support `associated_data` | Upgrade Vault (the integration tests run against 1.19) |
| `503 Service Unavailable` | Vault is sealed, or electing a leader, beyond the retries | Unseal Vault; check its HA status |
| `no answer within` | No answer within the timeout, on every attempt | Check the address and network path |
| `IllegalStateException` ... `token source` | The token source supplied no token, or one with spaces or non-ASCII characters | Check what the source reads |
| `CancellationException` ... `supplied no token within` | The token source didn't answer within the timeout | Check the source's login |

Reading a key file fails before Vault is called; see
[Wrap keys with AWS KMS](use-aws-kms.md#if-something-goes-wrong) for those errors.
