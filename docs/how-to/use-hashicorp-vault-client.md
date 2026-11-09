# Call Vault's API with the HashiCorp Vault client

This page uses `VaultClient`, from the artifact `hkdfguard-integration-hashicorpvault`, to call
HashiCorp Vault's HTTP API from Java: logging in, managing tokens, the KV and cubbyhole secrets
engines, the transit engine, and, through generic methods, anything else Vault exposes. It's a port
of HashiCorp's [vault-client-go](https://github.com/hashicorp/vault-client-go), generated from the
same OpenAPI spec but only for the endpoints HkdfGuard needs, and the Java counterpart of .NET's
`HkdfGuard.Integration.HashiCorpVault`. It holds Vault tokens the way the rest of HkdfGuard does:
only in protected form.

To read secrets into memory your application uses, prefer `HashiCorpVaultSecretCacheImpl` (artifact
`hkdfguard-cache-hashicorpvault`). It reads each secret straight into an array of its own and keeps
it encrypted. `VaultClient` returns response data as ordinary `String`s and `JsonValue`s, like any
other API client.

## 1. Add the artifact

```xml
<dependency>
  <groupId>io.github.runsecure</groupId>
  <artifactId>hkdfguard-integration-hashicorpvault</artifactId>
  <version>0.9.1</version>
</dependency>
```

It needs Java 21 or later and brings no third-party dependency: requests go through the JDK's
`java.net.http`. The module is `io.github.runsecure.hkdfguard.integration.hashicorpvault`.

## 2. Create a client

A client needs a token protector: a protector on your application's key ring, created for
`VaultClient.TOKEN_PURPOSE`. Every token the client holds is encrypted with it.

```java
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultClient;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultClientOptions;
import java.net.URI;

// keyRing is your application's KeyRing; see the README's example.
var tokenProtector = keyRing.createProtector(VaultClient.TOKEN_PURPOSE);

var vault = new VaultClient(tokenProtector, VaultClientOptions.builder()
        .address(URI.create("https://vault.example.com:8200"))
        .build());
```

Or take every setting from the environment variables vault-client-go and the `vault` CLI read
(`VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT` and the rest):

```java
var vault = new VaultClient(tokenProtector, VaultClientOptions.fromEnvironment(tokenProtector));
```

`fromEnvironment` protects `VAULT_TOKEN` with the protector you pass. Given null, it ignores
`VAULT_TOKEN`. Change what it read with `toBuilder()`.

Close the client when you're done with it, to release its connections.

To trust a private CA or present a client certificate, set `tls` to a `VaultTlsOptions`. It takes
PEM, as vault-client-go does, or a password-protected PKCS#12 or JKS trust store
(`trustStoreFile`) and client key store (`clientKeyStoreFile`). A store's password is given
encrypted, by a protector on your key ring created for `VaultTlsOptions.PASSWORD_PURPOSE`
(`VaultTlsOptions.protectPassword`), and decrypted only while the store is read. The transit key
wrapper and the secret cache take the same `VaultTlsOptions` through their own `tls` option.

> **Security:** The address must be `https`. Plain `http` is allowed only on a loopback address (a
> local Vault Agent or dev server), or when you set `allowUnencryptedHttp`, because every request
> carries a token.

## 3. Authenticate

Log in with any auth method. The `auth()` methods are generated, one per endpoint. The token in the
response is protected as the response is read, so it never becomes a `String`. Hand it straight to
the client:

```java
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.AppRoleLoginRequest;

var login = vault.auth().appRoleLoginAsync(new AppRoleLoginRequest()
        .setRoleId(roleId)
        .setSecretId(secretId)).join();
vault.setToken(login.auth().clientToken());
```

For a token you already hold, `vault.setToken(token)` protects it and keeps only the protected form.
It takes any `CharSequence`: pass `CharBuffer.wrap(chars)` to keep the token out of `String`, and
clear the array afterwards. To log in, renew and replace tokens on your own schedule, implement
`VaultTokenProvider`; the client asks it for a protected token on every request.

These are the same token types `HashiCorpVaultSecretCacheImpl` takes. A protected token only works
for the protector it was protected with, though, and the cache's purpose
(`HashiCorpVaultSecretCacheImpl.TOKEN_PURPOSE`) isn't the client's, so protect a token separately
for each. The transit key wrapper takes a `VaultTokenSource` instead, because it runs before there
is a key ring.

## 4. Call Vault

The generated methods are grouped as vault-client-go groups them. Only a subset of Vault's API is
generated: the endpoints listed in `generator.json`.

| Group | What it has |
|---|---|
| `vault.auth()` | Every auth method's login (`appRoleLoginAsync`, `kubernetesLoginAsync`, `awsLoginAsync`, `certLoginAsync`, `jwtLoginAsync`, ...), the JWT/OIDC browser flow and Okta push verification, and creating, looking up, renewing and revoking tokens |
| `vault.secrets()` | The KV version 2 and 1 engines, cubbyhole, and the whole transit engine (encrypt, decrypt, rewrap, data keys, sign, verify, HMAC, random bytes, and creating, rotating, configuring and trimming keys) |
| `vault.system()` | Health, seal status, leader status, the list of mounts, and wrapping (wrap, unwrap, rewrap, lookup) |

Configuring auth methods and other secrets engines, policies, identity and the rest of `sys/` aren't
generated: use the generic methods below, or add them to `generator.json` and regenerate. Each
generated method is named after the endpoint's operation ID (`kv-v2-read` is `kvV2ReadAsync`). It
takes the path's parameters, a typed request body and the query parameters, with an overload that
also takes `VaultRequestOptions`. It returns a `CompletableFuture` of a `VaultResponse` whose data is
a typed model from the `schema` package, or a `Map<String, JsonValue>` where Vault's spec doesn't
type the response.

```java
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultRequestOptions;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2WriteRequest;
import java.util.Map;

// The engine's default mount is "kv-v2"; a dev server mounts KV version 2 at "secret".
var kv = VaultRequestOptions.builder().mountPath("secret").build();

vault.secrets().kvV2WriteAsync("myapp/config", new KvV2WriteRequest()
        .setData(Map.of("feature", "on")), kv).join();

var config = vault.secrets().kvV2ReadAsync("myapp/config", kv).join();
var feature = config.data().getData().get("feature").asString();

var mounts = vault.system().mountsListSecretsEnginesAsync().join();
```

The generic methods reach any path, typed or not:

```java
var raw = vault.readAsync("sys/mounts").join();
vault.writeAsync("secret/data/myapp/flags", Map.of("data", Map.of("beta", true))).join();
var keys = vault.listAsync("secret/metadata/myapp").join();
vault.deleteAsync("secret/metadata/myapp/flags").join();
```

A request body is written as JSON from a `Map`, `List`, `String`, `char[]`, number, boolean, model
or `JsonValue`. A `char[]` is written without becoming a `String`, and the body is held in an array
that is zeroed once the request is done. `writeFromBytesAsync` and `writeFromStreamAsync` send a
body you've already encoded. `readRawAsync` returns Vault's response unparsed, as a
`VaultRawResponse` whose body you read and close.

`VaultRequestOptions` sets things for one request: another token, a namespace, extra headers or
query parameters, MFA credentials, response wrapping, callbacks, or a forwarding mode. The client's
own `set...` methods set them for every later request, and a request's settings win over the
client's. A request callback is handed the request's `HttpRequest.Builder` before the token is
added; a response callback gets the request without its token, the status and the headers.

Every request runs on a virtual thread of its own and returns at once. Cancelling the returned
future abandons the request.

### Wrap and unwrap a response

```java
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2ReadResponse;
import java.time.Duration;

var wrapped = vault.secrets().kvV2ReadAsync("myapp/config",
        kv.toBuilder().responseWrappingTtl(Duration.ofMinutes(5)).build()).join();
var unwrapped = vault.unwrapAsync(wrapped.wrapInfo().token(), KvV2ReadResponse::fromJson).join();
```

The wrapping token is protected by this client's protector. A process with a different key ring
can't use it as it is.

### Handle errors

The future fails with `VaultResponseException` when Vault refuses a request, carrying Vault's
status and error messages, and with `VaultRedirectException` for a redirect the client won't
follow. Both extend `VaultRequestException`, which the cache and the transit key wrapper fail with
too. A request that gets no answer fails with the `IOException` `java.net.http` threw. One that
outlives `requestTimeout` (60 seconds by default) fails with `TimeoutException`. An answer that
isn't the JSON expected fails with `VaultJsonException`.

```java
try {
    vault.secrets().kvV2ReadAsync("myapp/missing", kv).join();
} catch (CompletionException e) {
    if (!VaultClient.isErrorStatus(e, 404))
        throw e;
    // No such secret.
}
```

## How it differs from vault-client-go

| | vault-client-go | `VaultClient` |
|---|---|---|
| Tokens | Plain strings (`SetToken(string)`) | Protected by the token protector; decrypted only into the request's header |
| Login and wrapping tokens in responses | Strings | Protected as they're read (`StaticVaultToken`) |
| A token lookup's `data.id` (the token itself) | A string | Left out unread: it's the token the caller already holds |
| 3xx not followed (303, 304, 308, or any with redirects off) | Success | `VaultResponseException` (or `VaultRedirectException`) |
| Response body size | Unlimited | At most 32 MiB (`MAX_RESPONSE_LENGTH`) |
| Address | Any scheme | `https`, or `http` on loopback; any other `http` needs `allowUnencryptedHttp` |
| Unix domain sockets | Yes | No: `java.net.http` can't connect to one |
| Redirects | Follows one, never `https` to `http` | Refused (`VaultRedirectException`) unless `followRedirects` is set; then one, never `https` to `http`, and only to the address's own origin or one `redirectOrigins` lists (the cluster's other nodes, for raft calls a standby redirects) |
| Address with a path | Path dropped | Kept as a prefix, for Vault behind a reverse proxy |
| Free-form values | `map[string]interface{}` | `Map<String, Object>` sent, `Map<String, JsonValue>` returned |
| Optional fields | Zero values left out (`omitempty`) | Boxed and nullable; null left out, so `false` and `0` can be sent |
| Response fields Vault types differently from its spec | Decoding fails | A number where the spec says string is read as its text |
| Rate limiting | `rate.Limiter` | `VaultRateLimiter`, the same token bucket |
| Retries, MFA, namespaces, replication, callbacks, TLS | Yes | Yes, as vault-client-go - except that a POST, PUT or PATCH that failed without an answer is resent only if it never connected |
| Generic paths (`readAsync`, `writeAsync`, ...) | Sent as given | `.` and `..` segments, `?`, `#`, `%`, backslashes, spaces and control characters refused (`IllegalArgumentException`) |
| Client certificate key | Read into strings | Parsed as bytes, zeroed once the key is made; a `clientCertificateKeyPem` stays in the options for their life, so prefer `clientCertificateKeyFile` |
| Every request | | Sends `X-Vault-Request: true`, as the `vault` CLI does |
| Typed endpoints | All 907 | The 103 `generator.json` names: logins and tokens, KV, cubbyhole, transit, and a few of `sys/` |

Unlike the .NET client, a token's header value is one `String` per request that can't be zeroed:
`java.net.http` takes a header's value only as a `String`. It is made for that request alone and
referenced by nothing once the request has been sent.

## Regenerate from a newer spec, or for other endpoints

The `src/generated/java` folder of `hkdfguard-integration-hashicorpvault` is produced by
`tools/hkdfguard-integration-hashicorpvault-generator` from the module's `openapi.json`, which is
vault-client-go's spec (Vault API 1.15.0) and the same file the .NET library is generated from. As
in vault-client-go, operations whose ID ends in `2`, `3` or `4` (alternative paths to the same
endpoint) or starts with `enterprise-stub` are left out, along with their schemas.

`generator.json`, beside the spec, narrows that to the endpoints HkdfGuard needs. Its `include`
list holds regular expressions matched against operation names in PascalCase, as .NET names its
methods, without `Async` (`"^KvV2"`, `"^AppRoleLogin$"`). Only the operations they match are
generated, with only the schemas those operations use. Each expression must match at least one
operation, so a typo, or an endpoint a newer spec has dropped, stops the generator instead of
quietly generating less. To generate another endpoint, add a pattern and regenerate. To generate
everything vault-client-go does, delete the file.

To update:

1. Replace `openapi.json` with the newer spec. The simplest source is vault-client-go's own
   `openapi.json`. A spec read from your own Vault must use generic mount paths
   (`{kv_v2_mount_path}` and so on), as vault-client-go's does: the generator turns those into
   `VaultRequestOptions.mountPath()` and needs a default for each.
2. From `hkdfguard-java`, run the generator with the JDK's source launcher. It needs no build and
   has no dependencies:

   ```bash
   java tools/hkdfguard-integration-hashicorpvault-generator/src/main/java/io/github/runsecure/hkdfguard/integration/hashicorpvault/generator/GeneratorCommand.java
   ```

   It reads `generator.json` beside the spec (or the file `--settings` names), rewrites only the
   files that changed, and deletes those no longer produced. `--spec` and `--output` choose other
   files.
3. Build and test. The generator's test `theGeneratedCode_IsWhatTheSpecGenerates` fails whenever the
   checked-in code isn't what the spec and `generator.json` generate, so a hand edit to
   `src/generated/java` doesn't survive. `theGeneratedApi_IsTheSubsetGeneratorJsonNames` pins the
   subset itself; update it when you change `generator.json` on purpose.

Keep the .NET library's `openapi.json` and `generator.json` the same as these, so the two clients
keep the same endpoints and models.

If the generator meets something it doesn't handle, such as an inline object with its own
properties or a header parameter, it stops with an `IllegalArgumentException` naming the operation
or schema. Extend `VaultClientGenerator` rather than editing its output.

## Run the integration tests

`VaultClientIntegrationTest` writes, reads and deletes secrets under `secret/hkdfguard-client-test/`
on a Vault dev server, wraps and unwraps a response, and creates and revokes a token. It runs only
when `HKDFGUARD_TEST_VAULT_TOKEN` is set and `HKDFGUARD_TEST_VAULT_ADDR` is a loopback address.
Otherwise it's reported as skipped.

```bash
docker run --rm -d --name vault-dev -p 8200:8200 hashicorp/vault server -dev -dev-root-token-id=dev-root
HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=dev-root \
  ./mvnw test -pl hkdfguard-integration-hashicorpvault -Dtest=VaultClientIntegrationTest
```
