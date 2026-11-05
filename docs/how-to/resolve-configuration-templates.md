# Resolve configuration templates from protected caches

This page fills the `${name}` items in a template, such as a connection string or a configuration
file, with secrets from HkdfGuard's protected caches. Everything it uses is in one module,
`hkdfguard-integration-configurationresolver`. That module is the Java port of .NET's
`HkdfGuard.Integration.ConfigurationResolver`, together with the parts of
[ConfigurationResolver](https://github.com/runsecure/configurationresolver-dotnet) that it needs:
the token, the reader, the resolver and the value-provider contract.

Any `ProtectedReadOnlyCache` can supply the values:

- a `ProtectedCacheImpl`, `FilePerSecretCacheImpl` or `JsonSecretsFileReadOnlyCacheImpl`
- a `ProtectedEnvironment`, for `enc::` values in your Spring configuration
- a remote secret store's cache: `HashiCorpVaultSecretCacheImpl`, `AwsSecretsManagerSecretCacheImpl`,
  `AzureKeyVaultSecretCacheImpl` or `GoogleSecretManagerSecretCacheImpl`

## 1. Install

```xml
<dependency>
  <groupId>io.github.runsecure</groupId>
  <artifactId>hkdfguard-integration-configurationresolver</artifactId>
  <version>${hkdfguard.version}</version>
</dependency>
```

Add the module for your cache too, such as `hkdfguard-cache-hashicorpvault`. Every class below is in
the package `io.github.runsecure.hkdfguard.integration.configurationresolver`.

## 2. Resolve a template

A template's key is the cache's name for the value, unchanged. For a remote cache that includes the
`secret#key` form, so `${app-config#password}` is the `password` key of the secret `app-config`.

```java
// secrets is any ProtectedReadOnlyCache, such as a HashiCorpVaultSecretCacheImpl.
var template = "Host=db.internal;Username=${app-config#user};Password=${app-config#password}";

var token = new DefaultToken();
var reader = new ConfigurationItemReaderImpl(token);
reader.readKeys(template);

var provider = new ProtectedCacheValueProvider(secrets);
provider.prefetchAsync(reader).join();

var resolver = new ConfigurationItemResolver(token, reader, provider);
var connectionString = new char[1024];
try {
    var length = resolver.resolve(template, connectionString);
    // use connectionString[0..length)
} finally {
    Arrays.fill(connectionString, '\0');
}
```

The resolver looks up only the keys the reader read from the template. Read the template from a
trusted source, since it decides which secrets are revealed. Write `$${name}` for the literal text
`${name}`.

> **Security:** Each value is decrypted into a scratch array that is zeroed once the value is
> copied into your destination. It never becomes a `String`. If resolving fails, the resolver wipes
> the destination. The destination can be a `char[]`, a `byte[]` for UTF-8, or any `CharBuffer` or
> `ByteBuffer`. A direct buffer lives outside the heap, so the garbage collector never copies it.

### Why prefetch

Value providers are synchronous. The first time a remote cache is asked for a secret, it fetches it,
and a synchronous lookup blocks the thread until the fetch returns. `prefetchAsync` asks the cache
for each of the reader's keys without blocking. The cache keeps every value it fetches, encrypted,
so `resolve` then reads only from memory.

Prefetching asks for each key once. A key the cache doesn't have is skipped then, and reported by
`resolve` as a `ConfigurationKeyException` with `ConfigurationKeyError.NOT_FOUND`. For a local
cache, prefetching does nothing and you can leave it out.

## 3. Combine it with other providers

Pass several providers, highest priority first. The first one that has a key supplies its value.
Any `ValueProvider` works. Extend `ValueProviderBase` for one over your own non-secret settings:

```java
var resolver = new ConfigurationItemResolver(token, reader,
        new ProtectedCacheValueProvider(secrets),
        mySettingsProvider);
```

Or with the builder:

```java
var builder = new ConfigurationResolverBuilderImpl().withToken(token).withReader(reader);
var resolver = ConfigurationResolverBuilderExtensions.addProtectedCache(builder, secrets).build();
```

## 4. Keep templates in the caches themselves

`ResolvingProtectedCacheCollection` resolves templates for you, on lookup. It works like
`ProtectedCacheCollectionImpl`: you add sources, and it checks them in order. When the value it finds
holds items, it resolves them from the same sources, encrypts the result under your key ring, and
caches it. Later lookups only decrypt the cached result. A value without items is answered by its
source, unchanged.

Because the collection is itself a `ProtectedReadOnlyCache`, anything that reads a cache can read
resolved templates without knowing they were templates:

```java
// keyRing is your application's KeyRing. local holds, say, the encrypted value
// "Host=db.internal;Username=${app-config#user};Password=${app-config#password}"
// under the name "orders.connection-string"; vault is a HashiCorpVaultSecretCacheImpl.
var secrets = new ResolvingProtectedCacheCollection(keyRing)
        .add(local)
        .add(vault);

var maxLength = secrets.findMaxDecryptedLengthAsync("orders.connection-string").join().orElseThrow();
var connectionString = new char[maxLength];
var length = secrets.decryptAsync("orders.connection-string", connectionString).join();
```

The async members look up the template and every value it names through each source's async
members, so a remote source doesn't block a thread. Items can also come from value providers that
are asked after every source, for values that aren't secret:

```java
var secrets = new ResolvingProtectedCacheCollection(keyRing)
        .add(local)
        .add(vault)
        .addValueProvider(mySettingsProvider);
```

> **Security:** Any value in any source that holds `${...}` is a template, and a template can name
> any value in any source. Add only sources you trust as much as the secrets they can reach.

Some things to know:

- **Resolved values are kept until you invalidate them.** A value a template uses can change, for
  example through an `addOrUpdate`, a configuration reload or a rotated remote secret. When it does,
  call `invalidate(name)` with the template's name, or `clear()`. The next lookup resolves it again.
  A resolution already under way when you call either doesn't cache its result.
- **Items are resolved one level deep.** An item whose value is itself a template inserts that
  template's text unresolved.
- **A template that names a missing value throws** `ConfigurationKeyException` on lookup, rather
  than reporting the template's name missing. A template that resolves to nothing is reported
  missing, as an empty value can't be cached.
- **Names match exactly**, as the sources' own names do. The collection keeps `Db` and `db` apart,
  even though HkdfGuard's caches otherwise ignore ASCII case.
- **Resolved values are capped** at `maxResolvedLength` bytes, 1 MiB by default. A longer one
  throws `IllegalStateException`. Set it, and the token, through
  `new ResolvingProtectedCacheCollection(keyRing, token, maxResolvedLength)`.

## Values as strings

`ValueProvider.findValue` returns a value as a `String`, which can't be wiped. The resolver never
calls it, and `ProtectedCacheValueProvider` throws `IllegalStateException` if anything else does.
When a caller truly needs strings, opt in:

```java
var provider = new ProtectedCacheValueProvider(secrets, true);
```

## Differences from .NET

- Spans become `CharBuffer` and `ByteBuffer`. A provider writes at the buffer's position and moves
  it past the value, in place of .NET's `out int written`. `TryGetValue` is `findValue`, returning
  an `Optional`.
- Interfaces drop the `I` prefix, and the classes implementing them end in `Impl`: .NET's
  `ConfigurationItemReader` is `ConfigurationItemReaderImpl`. `init` properties become `with...`
  methods that return a new resolver.
- A destination that is too small throws `DestinationTooSmallException`, an
  `IllegalArgumentException`, since Java has no parameter name to tell the case apart.
- Only the parts of ConfigurationResolver this integration uses are ported. The file-secret,
  environment-variable and dictionary providers, `SecretBuffer`, and the
  Microsoft.Extensions.Configuration support are not.
