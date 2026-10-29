package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import static io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.FakeTransit.Answer;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.testsupport.WindowsTempDirectory;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The wrapper's real HttpClient against a fake transit engine on loopback. */
class HashiCorpVaultTransitKeyWrapperImplTest {
    private static final String CONTEXT = "hkdfguard.test";

    private static final String CONTEXT_BASE64 = Base64.getEncoder().encodeToString(CONTEXT.getBytes(StandardCharsets.UTF_8));

    private static final String KEY_NAME = FakeTransit.KEY_NAME;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final FakeTransit vault = track(new FakeTransit());

    @AfterEach
    void closeEverything() throws Exception {
        Collections.reverse(closeables);
        for (var closeable : closeables)
            closeable.close();
    }

    private <T extends AutoCloseable> T track(T closeable) {
        closeables.add(closeable);
        return closeable;
    }

    private HashiCorpVaultTransitKeyWrapperImpl create() {
        return create(CONTEXT);
    }

    private HashiCorpVaultTransitKeyWrapperImpl create(String context) {
        return create(context, options -> {
        });
    }

    private HashiCorpVaultTransitKeyWrapperImpl create(String context, Consumer<HashiCorpVaultTransitKeyWrapperOptions.Builder> options) {
        return create(vault.address(), KEY_NAME, context, new FakeTokenSource(), null, options);
    }

    private HashiCorpVaultTransitKeyWrapperImpl createWith(VaultTokenSource tokens) {
        return create(vault.address(), KEY_NAME, CONTEXT, tokens, null, options -> {
        });
    }

    // A wrapper with its own HttpClient unless options supply one. No backoff, only each retry's
    // 0-100 ms of jitter, so a test that meets a 5xx stays quick.
    private HashiCorpVaultTransitKeyWrapperImpl create(URI address, String keyName, String context, VaultTokenSource tokens,
            KeyFileTrust keyFileTrust, Consumer<HashiCorpVaultTransitKeyWrapperOptions.Builder> options) {
        var builder = HashiCorpVaultTransitKeyWrapperOptions.builder().retryDelay(Duration.ZERO);
        options.accept(builder);
        return track(new HashiCorpVaultTransitKeyWrapperImpl(address, keyName, tokens, context, keyFileTrust, builder.build()));
    }

    private static HashiCorpVaultTransitKeyWrapperImpl construct(URI address, String keyName, String context,
            HashiCorpVaultTransitKeyWrapperOptions options) {
        return new HashiCorpVaultTransitKeyWrapperImpl(address, keyName, new FakeTokenSource(), context, null, options);
    }

    private static byte[] wrap(HashiCorpVaultTransitKeyWrapperImpl wrapper, byte[] dek) {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        return Arrays.copyOf(wrapped, await(wrapper.wrapAsync(dek, wrapped)));
    }

    private static byte[] generate(HashiCorpVaultTransitKeyWrapperImpl wrapper) {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        return Arrays.copyOf(wrapped, await(wrapper.generateAndWrapAsync(wrapped)));
    }

    private static byte[] random(int length) {
        return FakeTransit.randomBytes(length);
    }

    private static byte[] filled(int length, int value) {
        var bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static byte[] ascii(String text) {
        return text.getBytes(StandardCharsets.US_ASCII);
    }

    private static String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static boolean isZero(char[] chars) {
        return ArrayUtility.isNullOrEmpty(chars);
    }

    // --- Construction ----------------------------------------------------------------------------

    @Test
    void theConstructor_RejectsMissingArguments() {
        var tokens = new FakeTokenSource();
        var address = vault.address();

        assertThrows(NullPointerException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(null, KEY_NAME, tokens));
        assertThrows(NullPointerException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(address, null, tokens));
        assertThrows(NullPointerException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(address, KEY_NAME, null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ".", "..", "team/kek", "my kek", "kek?x=1", "kék", "kek#1", "kek%2F"})
    void theConstructor_RejectsAKeyNameThatIsNotOne(String keyName) {
        var address = vault.address();

        assertThrows(IllegalArgumentException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(address, keyName, new FakeTokenSource()));
    }

    @Test
    void theConstructor_AcceptsTheLongestKeyName_AndRejectsOneOverIt() {
        var address = vault.address();
        var longest = "k".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_KEY_NAME_LENGTH);

        new HashiCorpVaultTransitKeyWrapperImpl(address, longest, new FakeTokenSource()).close();
        new HashiCorpVaultTransitKeyWrapperImpl(address, "my-app_kek.v2", new FakeTokenSource()).close();
        assertThrows(IllegalArgumentException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(address, longest + "k", new FakeTokenSource()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"relative/path", "vault.test:8200", "http://vault.example.com:8200", "http://10.0.0.1:8200", "http://[::2]",
            "ftp://127.0.0.1", "ftp://vault.example.com", "https://user:pass@vault.example.com:8200", "https://vault.example.com:8200/?x=1",
            "https://vault.example.com:8200/#f", "https:///no-host"})
    void theConstructor_RejectsAnAddressThatWouldExposeTheTokenOrDeks(String address) {
        var uri = URI.create(address);

        assertThrows(IllegalArgumentException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(uri, KEY_NAME, new FakeTokenSource()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://127.0.0.1:8200", "http://localhost:8200", "http://[::1]:8200", "http://127.1.2.3",
            "https://vault.example.com:8200", "HTTPS://vault.example.com/prefix/"})
    void theConstructor_AcceptsHttpsAnywhere_AndHttpOnlyOnLoopback(String address) {
        new HashiCorpVaultTransitKeyWrapperImpl(URI.create(address), KEY_NAME, new FakeTokenSource()).close();
    }

    @Test
    void theConstructor_AcceptsTheLongestContext_AndRejectsOneOverIt() {
        var dek = random(32);
        var wrapper = create("c".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_CONTEXT_LENGTH));
        var revealed = new byte[32];
        assertEquals(32, await(wrapper.unwrapAsync(wrap(wrapper, dek), revealed)));
        assertArrayEquals(dek, revealed);

        var address = vault.address();
        // 1024 bytes in UTF-8 is the limit, whatever the characters: 513 two-byte ones are over it.
        assertThrows(IllegalArgumentException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(address, KEY_NAME, new FakeTokenSource(),
                "c".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_CONTEXT_LENGTH + 1)));
        assertThrows(IllegalArgumentException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(address, KEY_NAME, new FakeTokenSource(),
                "é".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_CONTEXT_LENGTH / 2 + 1)));
    }

    @Test
    void theConstructor_RejectsAContextWithAnUnpairedSurrogate() {
        var address = vault.address();

        assertThrows(IllegalArgumentException.class, () -> new HashiCorpVaultTransitKeyWrapperImpl(address, KEY_NAME, new FakeTokenSource(), "a\uD800b"));
    }

    @Test
    void theConstructor_RejectsInvalidOptions() {
        var address = vault.address();
        Consumer<HashiCorpVaultTransitKeyWrapperOptions.Builder> nothing = options -> {
        };
        List<Consumer<HashiCorpVaultTransitKeyWrapperOptions.Builder>> invalid = List.of(
                options -> options.mountPath(""),
                options -> options.mountPath(null),
                options -> options.mountPath("transit/../sys"),
                options -> options.mountPath("/transit"),
                options -> options.mountPath("transit/"),
                options -> options.mountPath("transit?x=1"),
                options -> options.namespace("team a"),
                options -> options.namespace(""),
                options -> options.namespace("team-a/../root"),
                options -> options.timeout(Duration.ZERO),
                options -> options.timeout(Duration.ofMillis(-1)),
                options -> options.retryCount(HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT - 1),
                options -> options.retryCount(HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_COUNT + 1),
                options -> options.retryDelay(Duration.ofMillis(-1)),
                options -> options.retryDelay(HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY.plusNanos(1)));
        for (var change : invalid) {
            var builder = HashiCorpVaultTransitKeyWrapperOptions.builder();
            change.accept(builder);
            var options = builder.build();
            assertThrows(IllegalArgumentException.class, () -> construct(address, KEY_NAME, null, options));
        }

        assertThrows(NullPointerException.class, () -> HashiCorpVaultTransitKeyWrapperOptions.builder().timeout(null));
        assertThrows(NullPointerException.class, () -> HashiCorpVaultTransitKeyWrapperOptions.builder().retryDelay(null));

        nothing.accept(HashiCorpVaultTransitKeyWrapperOptions.builder());
        construct(address, KEY_NAME, null, HashiCorpVaultTransitKeyWrapperOptions.builder()
                .retryCount(HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT).retryDelay(Duration.ZERO).build()).close();
        construct(address, KEY_NAME, null, HashiCorpVaultTransitKeyWrapperOptions.builder()
                .retryCount(HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_COUNT)
                .retryDelay(HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY).build()).close();
    }

    @Test
    void theDefaults_AreVaultsOwn() {
        var options = HashiCorpVaultTransitKeyWrapperOptions.builder().build();

        assertEquals("transit", options.mountPath());
        assertNull(options.namespace());
        assertEquals(Duration.ofSeconds(30), options.timeout());
        assertEquals(3, options.retryCount());
        assertEquals(Duration.ofMillis(200), options.retryDelay());
        assertNull(options.httpClient());
        assertFalse(options.allowRedirects());

        var changed = options.toBuilder().mountPath("transit/team-a").namespace("team-a").retryCount(5).build();
        assertEquals("transit/team-a", changed.mountPath());
        assertEquals("team-a", changed.namespace());
        assertEquals(5, changed.retryCount());
        assertEquals(Duration.ofSeconds(30), changed.timeout());
    }

    @ParameterizedTest
    @EnumSource(value = HttpClient.Redirect.class, names = {"NORMAL", "ALWAYS"})
    void aClientThatFollowsRedirects_IsRefused_UnlessExplicitlyAllowed(HttpClient.Redirect redirect) {
        var client = track(HttpClient.newBuilder().followRedirects(redirect).build());
        var address = vault.address();

        var e = assertThrows(IllegalArgumentException.class,
                () -> construct(address, KEY_NAME, null, HashiCorpVaultTransitKeyWrapperOptions.builder().httpClient(client).build()));
        assertTrue(e.getMessage().contains("allowRedirects"));

        construct(address, KEY_NAME, null, HashiCorpVaultTransitKeyWrapperOptions.builder().httpClient(client).allowRedirects(true).build()).close();
    }

    @Test
    void theConstructor_MakesNoCall() {
        create();
        new HashiCorpVaultTransitKeyWrapperImpl(vault.address(), KEY_NAME, new FakeTokenSource()).close();

        assertEquals(List.of(), vault.requests());
    }

    // --- Wrap and unwrap -------------------------------------------------------------------------

    @Test
    void wrapThenUnwrap_RoundTripsTheDek() {
        var wrapper = create();
        var dek = random(32);

        var wrapped = wrap(wrapper, dek);
        var revealed = new byte[32];

        assertTrue(new String(wrapped, StandardCharsets.US_ASCII).startsWith("vault:v1:"));
        assertEquals(32, await(wrapper.unwrapAsync(wrapped, revealed)));
        assertArrayEquals(dek, revealed);
    }

    @Test
    void wrapAsync_EncryptsUnderTheKeyWithTheContext_SendingExactlyTheDotNetBody() {
        var wrapper = create();
        var dek = random(32);

        wrap(wrapper, dek);

        var request = vault.requests().getFirst();
        assertEquals(1, vault.requests().size());
        assertEquals("encrypt", request.operation());
        assertEquals(KEY_NAME, request.key());
        assertEquals("{\"plaintext\":\"" + base64(dek) + "\",\"associated_data\":\"" + CONTEXT_BASE64 + "\"}", request.bodyText());
        assertEquals(FakeTransit.TOKEN, request.token());
        assertEquals("true", request.vaultRequest());
        assertEquals("application/json", request.contentType());
        assertNull(request.namespace());
        assertEquals(List.of(), vault.unexpectedRequests());
    }

    @Test
    void unwrapAsync_DecryptsUnderTheKeyWithTheContext_SendingExactlyTheDotNetBody() {
        var wrapper = create();
        var wrapped = wrap(wrapper, random(32));

        await(wrapper.unwrapAsync(wrapped, new byte[32]));

        var request = vault.requests().getLast();
        assertEquals("decrypt", request.operation());
        assertEquals(KEY_NAME, request.key());
        assertEquals("{\"ciphertext\":\"" + new String(wrapped, StandardCharsets.US_ASCII) + "\",\"associated_data\":\"" + CONTEXT_BASE64 + "\"}",
                request.bodyText());
    }

    @Test
    void withoutAContext_TheBodiesCarryNoAssociatedData() {
        var wrapper = create(null);
        var dek = random(20);

        var wrapped = wrap(wrapper, dek);
        await(wrapper.unwrapAsync(wrapped, new byte[32]));

        var requests = vault.requests();
        assertEquals("{\"plaintext\":\"" + base64(dek) + "\"}", requests.get(0).bodyText());
        assertEquals("{\"ciphertext\":\"" + new String(wrapped, StandardCharsets.US_ASCII) + "\"}", requests.get(1).bodyText());
    }

    @Test
    void wrapAsync_ZeroesTheRequestBodyAndTheTokenBufferOnceDone_AndLeavesTheCallersPlaintextAlone() {
        var client = track(new CapturingHttpClient());
        var tokens = new FakeTokenSource();
        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, tokens, null, options -> options.httpClient(client));
        var dek = random(32);
        var copy = dek.clone();

        wrap(wrapper, dek);

        // The body went out from the wrapper's own array, not a copy of it...
        assertTrue(client.everyBodyArrayAccessible());
        var sent = client.bodyArrays();
        assertEquals(1, sent.size());
        assertEquals(vault.requests().getFirst().body().length, sent.getFirst().length);
        // ...which, like the token's buffer, is zeroed once the call is done.
        assertTrue(ArrayUtility.isNullOrEmpty(sent.getFirst()));
        assertTrue(isZero(tokens.destinations().getFirst()));
        assertEquals(HashiCorpVaultTransitKeyWrapperImpl.MAX_TOKEN_LENGTH, tokens.destinations().getFirst().length);
        assertArrayEquals(copy, dek);
    }

    @Test
    void wrapAsync_ZeroesTheRequestBody_WhenTheCallFails() {
        var client = track(new CapturingHttpClient());
        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, FakeTokenSource.giving("hvs.revoked"), null, options -> options.httpClient(client));

        assertFailsWith(CryptographicException.class, wrapper.wrapAsync(random(32), new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(1, client.bodyArrays().size());
        assertTrue(ArrayUtility.isNullOrEmpty(client.bodyArrays().getFirst()));
    }

    @Test
    void wrapAsync_RetriedAfterATransientFailure_SendsTheSameBodyAgain_ThenZeroesIt() {
        var client = track(new CapturingHttpClient());
        vault.answer = (request, count) -> count == 1 ? new Answer(503, "{\"errors\":[\"Vault is sealed\"]}") : null;
        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, new FakeTokenSource(), null, options -> options.httpClient(client));
        var dek = random(32);

        var revealed = new byte[32];
        await(wrapper.unwrapAsync(wrap(wrapper, dek), revealed));

        assertArrayEquals(dek, revealed);
        var requests = vault.requests();
        assertArrayEquals(requests.get(0).body(), requests.get(1).body());
        var sent = client.bodyArrays();
        assertSame(sent.get(0), sent.get(1));
        assertTrue(ArrayUtility.isNullOrEmpty(sent.get(0)));
    }

    @Test
    void generateAndWrapAsync_WithNoContext_HasVaultGenerateAWrappedAes256KeyOnly() {
        var wrapper = create(null);

        var wrapped = generate(wrapper);
        var revealed = new byte[32];
        int revealedLength = await(wrapper.unwrapAsync(wrapped, revealed));

        var requests = vault.requests();
        assertEquals("datakey", requests.get(0).operation());
        assertEquals(KEY_NAME, requests.get(0).key());
        assertEquals("{\"bits\":256}", requests.get(0).bodyText());
        assertNull(requests.get(1).field("associated_data"));
        assertEquals(HashiCorpVaultTransitKeyWrapperImpl.GENERATED_KEY_LENGTH, revealedLength);
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void withAnEmptyContext_NoneIsSent_AndVaultGenerates() {
        var wrapper = create("");

        var wrapped = wrap(wrapper, random(32));
        await(wrapper.unwrapAsync(wrapped, new byte[32]));
        generate(wrapper);

        for (var request : vault.requests())
            assertNull(request.field("associated_data"));
        assertEquals("datakey", vault.requests().getLast().operation());
    }

    @Test
    void generateAndWrapAsync_WithAContext_GeneratesHere_AndEncryptsWithIt() {
        // datakey/wrapped ignores associated_data, so it can't bind a context.
        var wrapper = create();

        var wrapped = generate(wrapper);
        var revealed = new byte[32];
        await(wrapper.unwrapAsync(wrapped, revealed));

        var request = vault.requests().getFirst();
        assertEquals("encrypt", request.operation());
        assertEquals(CONTEXT_BASE64, request.field("associated_data"));
        assertArrayEquals(Base64.getDecoder().decode(request.field("plaintext")), revealed);
        assertEquals(HashiCorpVaultTransitKeyWrapperImpl.GENERATED_KEY_LENGTH, revealed.length);
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void theContext_IsEncodedAsUtf8() {
        var context = "contexte é中😀";
        var wrapper = create(context);

        wrap(wrapper, random(32));

        assertEquals(base64(context.getBytes(StandardCharsets.UTF_8)), vault.requests().getFirst().field("associated_data"));
    }

    @Test
    void unwrapAsync_KeepsRevealingKeyFilesMadeBeforeTheKeyRotated_UntilTheirVersionIsTooOld() {
        var wrapper = create();
        var dek = random(32);
        var before = wrap(wrapper, dek);
        vault.rotate(KEY_NAME);
        var after = wrap(wrapper, random(32));

        assertTrue(new String(before, StandardCharsets.US_ASCII).startsWith("vault:v1:"));
        assertTrue(new String(after, StandardCharsets.US_ASCII).startsWith("vault:v2:"));
        var revealed = new byte[32];
        assertEquals(32, await(wrapper.unwrapAsync(before, revealed)));
        assertArrayEquals(dek, revealed);

        vault.setMinDecryptionVersion(KEY_NAME, 2);
        var result = filled(32, 0xAA);
        var e = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(before, result));

        assertEquals("Vault transit unwrap failed for key '" + KEY_NAME
                + "': Vault answered 400 Bad Request: ciphertext or signature version is disallowed by policy (too old)", e.getMessage());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
        assertEquals(32, await(wrapper.unwrapAsync(after, new byte[32])));
    }

    @Test
    void unwrapAsync_UnderAnotherKey_FailsNamingVaultsAnswer_AndZeroesTheResult() {
        vault.addKey("other-kek");
        var other = create(vault.address(), "other-kek", CONTEXT, new FakeTokenSource(), null, options -> {
        });
        var wrapped = wrap(other, random(32));

        var wrapper = create();
        var result = filled(32, 0xAA);
        var e = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped, result));

        assertEquals("Vault transit unwrap failed for key '" + KEY_NAME + "': Vault answered 400 Bad Request: cipher: message authentication failed",
                e.getMessage());
        assertEquals(400, assertInstanceOf(VaultRequestException.class, e.getCause()).statusCode());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
        assertEquals(2, vault.requests().size());
        assertEquals("other-kek", vault.requests().get(0).key());
        assertEquals(KEY_NAME, vault.requests().get(1).key());
    }

    @Test
    void unwrapAsync_UnderAnotherContext_OrNone_Fails() {
        var wrapper = create();
        var other = create("other");
        var none = create(null);
        var wrapped = wrap(wrapper, random(32));

        assertFailsWith(CryptographicException.class, other.unwrapAsync(wrapped, new byte[32]));
        assertFailsWith(CryptographicException.class, none.unwrapAsync(wrapped, new byte[32]));
    }

    @Test
    void unwrapAsync_WhenTampered_Fails() {
        var wrapper = create();
        var wrapped = wrap(wrapper, random(32));
        // Another base64 character, so it still reaches Vault and fails there.
        wrapped[12] = wrapped[12] == 'A' ? (byte) 'B' : (byte) 'A';

        var e = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped, new byte[32]));

        assertEquals(400, assertInstanceOf(VaultRequestException.class, e.getCause()).statusCode());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "vault:v1:", "vault:v:AAAA", "vault:x1:AAAA", "vault:v12345678901:AAAA", "vault:v1:AA\"},\"x\":\"AA",
            "vault:v1:AA AA", "VAULT:v1:AAAA", "vault:v1:AA\\u0041", "AAAA"})
    void unwrapAsync_OfSomethingThatIsNotACiphertext_FailsWithoutCallingVault(String wrapped) {
        var wrapper = create();

        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped.getBytes(StandardCharsets.UTF_8), new byte[32]));

        assertEquals(List.of(), vault.requests());
    }

    @Test
    void unwrapAsync_OverTheKeyFileLimit_FailsWithoutCallingVault() {
        var wrapper = create();
        var wrapped = ascii("vault:v1:" + "A".repeat(WrappedKeyLimits.MAX_BYTES));

        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped, new byte[32]));

        assertEquals(List.of(), vault.requests());
    }

    @Test
    void unwrapAsync_WhenTheKeyDoesNotFit_FailsAndZeroesTheResult() {
        var wrapper = create();
        var wrapped = wrap(wrapper, random(32));

        var result = filled(16, 0xAA);
        assertFailsWith(IllegalArgumentException.class, wrapper.unwrapAsync(wrapped, result));

        assertTrue(ArrayUtility.isNullOrEmpty(result));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, HashiCorpVaultTransitKeyWrapperImpl.MAX_PLAINTEXT_LENGTH + 1})
    void wrapAsync_RejectsAPlaintextOutOfBounds_WithoutCallingVault(int size) {
        var wrapper = create();

        assertThrows(IllegalArgumentException.class, () -> wrapper.wrapAsync(new byte[size], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(List.of(), vault.requests());
    }

    @Test
    void theCalls_RejectNullArguments() {
        var wrapper = create();

        assertThrows(NullPointerException.class, () -> wrapper.wrapAsync(null, new byte[32]));
        assertThrows(NullPointerException.class, () -> wrapper.wrapAsync(new byte[32], null));
        assertThrows(NullPointerException.class, () -> wrapper.unwrapAsync(null, new byte[32]));
        assertThrows(NullPointerException.class, () -> wrapper.unwrapAsync(ascii("vault:v1:AAAA"), null));
        assertThrows(NullPointerException.class, () -> wrapper.generateAndWrapAsync(null));
        assertThrows(NullPointerException.class, () -> create(null).generateAndWrapAsync(null));
        assertThrows(NullPointerException.class, () -> wrapper.readKeyFileAsync(null));
    }

    @Test
    void wrapAsync_OfTheLargestPlaintext_FitsTheKeyFileLimit() {
        var wrapper = create();
        var dek = random(HashiCorpVaultTransitKeyWrapperImpl.MAX_PLAINTEXT_LENGTH);

        var wrapped = wrap(wrapper, dek);
        var revealed = new byte[dek.length];

        assertTrue(wrapped.length <= WrappedKeyLimits.MAX_BYTES);
        assertEquals(dek.length, await(wrapper.unwrapAsync(wrapped, revealed)));
        assertArrayEquals(dek, revealed);
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 31, 32, 33})
    void wrapThenUnwrap_RoundTripsEveryBase64PaddingLength(int length) {
        var wrapper = create();
        var dek = random(length);

        var revealed = new byte[length];
        assertEquals(length, await(wrapper.unwrapAsync(wrap(wrapper, dek), revealed)));

        assertArrayEquals(dek, revealed);
        assertEquals(base64(dek), vault.requests().getFirst().field("plaintext"));
    }

    @Test
    void wrapAsync_WhenResultIsTooSmall_Fails_LeavingItAsItWas() {
        var wrapper = create();
        var result = filled(8, 0xAA);

        assertFailsWith(IllegalArgumentException.class, wrapper.wrapAsync(new byte[32], result));

        assertArrayEquals(filled(8, 0xAA), result);
    }

    @Test
    void wrapAsync_AndUnwrapAsync_WriteIntoTheStartOfALargerResult() {
        var wrapper = create();
        var dek = random(32);

        var wrapped = filled(WrappedKeyLimits.MAX_BYTES, 0xAA);
        int wrappedLength = await(wrapper.wrapAsync(dek, wrapped));
        assertArrayEquals(filled(wrapped.length - wrappedLength, 0xAA), Arrays.copyOfRange(wrapped, wrappedLength, wrapped.length));

        var revealed = filled(64, 0xAA);
        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, wrappedLength), revealed)));
        assertArrayEquals(dek, Arrays.copyOf(revealed, 32));
        assertArrayEquals(filled(32, 0xAA), Arrays.copyOfRange(revealed, 32, 64));
    }

    // --- Vault's answers -------------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "not JSON|<html>proxy</html>",
            "not an object|[]",
            "no data|{\"data\":null}",
            "data not an object|{\"data\":\"x\"}",
            "no ciphertext|{\"data\":{\"key_version\":1}}",
            "ciphertext not a string|{\"data\":{\"ciphertext\":7}}",
            "ciphertext empty|{\"data\":{\"ciphertext\":\"\"}}",
            "ciphertext twice|{\"data\":{\"ciphertext\":\"vault:v1:AAAA\",\"ciphertext\":\"vault:v1:BBBB\"}}",
            "not a ciphertext|{\"data\":{\"ciphertext\":\"AAAA\"}}",
            "trailing data|{\"data\":{\"ciphertext\":\"vault:v1:AAAA\"}} {}",
            "truncated|{\"data\":{\"ciphertext\":\"vault:v1:AAAA\"}",
            "a parameter ignored|{\"data\":{\"ciphertext\":\"vault:v1:AAAA\"},\"warnings\":[\"Endpoint ignored these unrecognized parameters: [associated_data]\"]}",
    })
    void wrapAsync_RefusesAnAnswerThatIsNotACiphertext(String because, String body) {
        vault.answer = (request, count) -> new Answer(200, body);
        var wrapper = create();

        var e = assertFailsWith(CryptographicException.class, wrapper.wrapAsync(new byte[32], new byte[2 * WrappedKeyLimits.MAX_BYTES]));

        assertTrue(e.getMessage().startsWith("Vault transit wrap for key '" + KEY_NAME + "'"), because + ": " + e.getMessage());
        assertEquals(1, vault.requests().size(), because);
    }

    @Test
    void wrapAsync_RefusesACiphertextOverTheKeyFileLimit() {
        vault.answer = (request, count) -> new Answer(200, FakeTransit.envelope(
                FakeTransit.Json.object("ciphertext", "vault:v1:" + "A".repeat(WrappedKeyLimits.MAX_BYTES))));
        var wrapper = create();

        var e = assertFailsWith(CryptographicException.class, wrapper.wrapAsync(new byte[32], new byte[2 * WrappedKeyLimits.MAX_BYTES]));

        assertTrue(e.getMessage().contains("a wrapped DEK is at most " + WrappedKeyLimits.MAX_BYTES), e.getMessage());
    }

    @Test
    void wrapAsync_NamesWhatWasWrongWithAnAnswer() {
        vault.answer = (request, count) -> new Answer(200, "{\"data\":{\"key_version\":1}}");
        var wrapper = create();

        var e = assertFailsWith(CryptographicException.class, wrapper.wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("Vault transit wrap for key '" + KEY_NAME + "' returned no ciphertext.", e.getMessage());
    }

    @Test
    void anEscapedAnswer_IsUnescaped() {
        // vault:v1:AB+/ with '+' as a \\u escape and '/' as \/, as a proxy re-encoding the answer might write it.
        vault.answer = (request, count) -> new Answer(200, "{\"data\":{\"ciphertext\":\"vault:v1:AB\\u002B\\/\"}}");
        var wrapper = create();

        assertArrayEquals(ascii("vault:v1:AB+/"), wrap(wrapper, new byte[32]));
    }

    @Test
    void anAnswerWithOtherWarnings_IsAccepted() {
        vault.answer = (request, count) -> new Answer(200,
                "{\"data\":{\"ciphertext\":\"vault:v1:AAAA\"},\"warnings\":[7,{\"unrecognized parameters\":1},\"some other warning\"]}");
        var wrapper = create();

        assertArrayEquals(ascii("vault:v1:AAAA"), wrap(wrapper, new byte[32]));
    }

    @Test
    void aVaultThatIgnoresTheContext_IsRefused_RatherThanWrappingUnbound() {
        vault.ignoresAssociatedData = true;
        var wrapper = create();

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(e.getMessage().contains("ignored a parameter"), e.getMessage());
        assertFailsWith(CryptographicException.class, wrapper.wrapAsync(random(32), new byte[WrappedKeyLimits.MAX_BYTES]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"data\":{\"plaintext\":\"not base64!\"}}", "{\"data\":{\"plaintext\":\"AAA\"}}", "{\"data\":{\"plaintext\":\"A===\"}}",
            "{\"data\":{\"plaintext\":\"AA=A\"}}", "{\"data\":{}}", "{\"data\":{\"plaintext\":\"\"}}", "{\"data\":{\"plaintext\":null}}",
            "{\"data\":{\"plaintext\":\"AAAA\"},\"warnings\":[\"Endpoint ignored these unrecognized parameters: [associated_data]\"]}"})
    void unwrapAsync_RefusesAnAnswerThatIsNotAPlaintext_AndZeroesTheResult(String body) {
        vault.answer = (request, count) -> new Answer(200, body);
        var wrapper = create();

        var result = filled(32, 0xAA);
        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(ascii("vault:v1:AAAA"), result));

        assertTrue(ArrayUtility.isNullOrEmpty(result));
    }

    @Test
    void anAnswerOverTheResponseLimit_IsRefused_AndNotRetried() {
        var huge = FakeTransit.envelope(FakeTransit.Json.object("ciphertext", "vault:v1:AAAA",
                "padding", "x".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_RESPONSE_LENGTH)));
        vault.answer = (request, count) -> new Answer(200, huge);
        var wrapper = create();

        var e = assertFailsWith(CryptographicException.class, wrapper.wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(e.getMessage().contains("over " + HashiCorpVaultTransitKeyWrapperImpl.MAX_RESPONSE_LENGTH), e.getMessage());
        assertEquals(1, vault.requests().size());
    }

    @Test
    void anAnswerOfExactlyTheResponseLimit_IsRead() {
        var body = FakeTransit.envelope(FakeTransit.Json.object("ciphertext", "vault:v1:AAAA", "padding", ""));
        var exact = body.replace("\"padding\":\"\"", "\"padding\":\"" + "x".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_RESPONSE_LENGTH - body.length()) + "\"");
        assertEquals(HashiCorpVaultTransitKeyWrapperImpl.MAX_RESPONSE_LENGTH, exact.length());
        vault.answer = (request, count) -> new Answer(200, exact);
        var wrapper = create();

        assertArrayEquals(ascii("vault:v1:AAAA"), wrap(wrapper, new byte[32]));
    }

    // --- Failures --------------------------------------------------------------------------------

    @Test
    void aVaultRefusal_BecomesACryptographicExceptionNamingVaultsErrors_AndIsNotRetried() {
        var wrapper = createWith(FakeTokenSource.giving("hvs.revoked"));

        var e = assertFailsWith(CryptographicException.class, wrapper.wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("Vault transit wrap failed for key '" + KEY_NAME + "': Vault answered 403 Forbidden: 1 error occurred:\n\t* permission denied\n\n",
                e.getMessage());
        var cause = assertInstanceOf(VaultRequestException.class, e.getCause());
        assertEquals(403, cause.statusCode());
        assertFalse(cause.isTransient());
        assertEquals(1, vault.requests().size());
        assertEquals("hvs.revoked", vault.requests().getFirst().token());
    }

    @Test
    void severalErrors_AreJoined() {
        vault.answer = (request, count) -> new Answer(400, "{\"errors\":[\"first\",\"second\"]}");
        var wrapper = create();

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(e.getMessage().endsWith("Vault answered 400 Bad Request: first; second"), e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"<html>bad gateway</html>", "{\"errors\":\"x\"}", "[]", "{}", "{\"errors\":[]}", ""})
    void aRefusalThatIsNotVaultsJson_IsReportedByItsStatus(String body) {
        vault.answer = (request, count) -> new Answer(404, body);
        var wrapper = create();

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(e.getMessage().endsWith("Vault answered 404 Not Found"), e.getMessage());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "503|{\"errors\":[\"Vault is sealed\"]}",
            "429|{\"errors\":[\"rate limit quota exceeded\"]}",
            "500|{\"errors\":[\"internal error\"]}",
            "502|<html>Bad Gateway</html>",
            "504|``",
    })
    void aTransientAnswer_IsRetried_AskingForTheTokenOnce(int status, String body) {
        vault.answer = (request, count) -> count <= 2 ? new Answer(status, body) : null;
        var tokens = new FakeTokenSource();
        var wrapper = createWith(tokens);
        var dek = random(32);

        var wrapped = wrap(wrapper, dek);

        assertEquals(3, vault.requests().size());
        assertEquals(1, tokens.calls());
        assertTrue(isZero(tokens.destinations().getFirst()));
        var revealed = new byte[32];
        await(wrapper.unwrapAsync(wrapped, revealed));
        assertArrayEquals(dek, revealed);
    }

    @ParameterizedTest
    @ValueSource(ints = {HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT, 4, HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_COUNT})
    void aTransientFailure_ThatOutlastsTheRetries_BecomesACryptographicException(int retryCount) {
        vault.answer = (request, count) -> new Answer(503, "{\"errors\":[\"Vault is sealed\"]}");
        var wrapper = create(CONTEXT, options -> options.retryCount(retryCount));

        var e = assertFailsWith(CryptographicException.class, wrapper.wrapAsync(random(32), new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(1 + retryCount, vault.requests().size());
        assertTrue(e.getMessage().endsWith("Vault answered 503 Service Unavailable: Vault is sealed"), e.getMessage());
        assertTrue(assertInstanceOf(VaultRequestException.class, e.getCause()).isTransient());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "400|{\"errors\":[\"bad request\"]}",
            "403|{\"errors\":[\"permission denied\"]}",
            "404|{\"errors\":[\"no handler for route\"]}",
            "501|{\"errors\":[]}",
            "307|``",
    })
    void anAnswerThatWouldRepeat_IsNotRetried(int status, String body) {
        vault.answer = (request, count) -> new Answer(status, body);
        var wrapper = create(null);

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(status, assertInstanceOf(VaultRequestException.class, e.getCause()).statusCode());
        assertEquals(1, vault.requests().size());
    }

    enum LostConnection { NO_ANSWER, DROPPED_MID_RESPONSE, ATTEMPT_TIMED_OUT }

    @ParameterizedTest
    @EnumSource(LostConnection.class)
    void aLostConnection_IsRetried(LostConnection how) {
        var wrapper = create(CONTEXT, options -> options.timeout(Duration.ofMillis(500)));
        vault.onRequest = exchange -> {
            if (vault.requests().size() > 1)
                return;

            switch (how) {
                case NO_ANSWER -> throw new IOException("The connection is dropped without an answer.");
                case DROPPED_MID_RESPONSE -> {
                    exchange.sendResponseHeaders(200, 200);
                    exchange.getResponseBody().write("{\"data\":{\"ciphertext\":\"vault:v1:AA".getBytes(StandardCharsets.UTF_8));
                    exchange.getResponseBody().flush();
                    throw new IOException("The connection is dropped mid-response.");
                }
                case ATTEMPT_TIMED_OUT -> sleepQuietly(2_000);
            }
        };
        var dek = random(32);

        var wrapped = wrap(wrapper, dek);

        assertEquals(2, vault.requests().size());
        var revealed = new byte[32];
        await(wrapper.unwrapAsync(wrapped, revealed));
        assertArrayEquals(dek, revealed);
    }

    @Test
    void anAttemptThatTimesOut_IsRetried_ThenReportedAsNoAnswer() {
        vault.onRequest = exchange -> sleepQuietly(5_000);
        var wrapper = create(null, options -> options.timeout(Duration.ofMillis(200)));

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT + 1, vault.requests().size());
        assertEquals("Vault transit generate-and-wrap failed for key '" + KEY_NAME + "': no answer within PT0.2S", e.getMessage());
        assertInstanceOf(HttpTimeoutException.class, e.getCause());
    }

    @Test
    void aBodyThatStalls_TimesOutWithinTheAttemptsTimeout_AndIsRetried() {
        var wrapper = create(null, options -> options.timeout(Duration.ofMillis(300)));
        vault.onRequest = exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().write("{\"data\":{\"ciphertext\":\"vault:v1:AA".getBytes(StandardCharsets.UTF_8));
            exchange.getResponseBody().flush();
            sleepQuietly(5_000);
            throw new IOException("Never finished.");
        };

        var started = System.nanoTime();
        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        var elapsed = Duration.ofNanos(System.nanoTime() - started);

        assertInstanceOf(HttpTimeoutException.class, e.getCause());
        assertTrue(e.getMessage().endsWith("no answer within PT0.3S"), e.getMessage());
        assertEquals(1 + HashiCorpVaultTransitKeyWrapperOptions.MIN_RETRY_COUNT, vault.requests().size());
        // Four attempts of 300 ms and three waits of at most 100 ms, far short of one stalled body.
        assertTrue(elapsed.compareTo(Duration.ofMillis(4_000)) < 0, elapsed.toString());
    }

    @Test
    void anUnreachableVault_IsRetried_ThenACryptographicExceptionWithTheIOException() throws IOException {
        int port;
        try (var socket = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            port = socket.getLocalPort();
        }
        var wrapper = create(URI.create("http://127.0.0.1:" + port + "/"), KEY_NAME, null, new FakeTokenSource(), null, options -> {
        });

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertInstanceOf(ConnectException.class, e.getCause());
        assertTrue(e.getMessage().startsWith("Vault transit generate-and-wrap failed for key '" + KEY_NAME + "': "), e.getMessage());
    }

    @Test
    void cancellingTheFuture_WhileVaultIsAnswering_AbandonsTheRequest_ZeroesTheResult_AndIsNotRetried() throws Exception {
        var wrapper = create();
        var wrapped = wrap(wrapper, random(32));
        var arrived = new CountDownLatch(1);
        vault.onRequest = exchange -> {
            arrived.countDown();
            sleepQuietly(5_000);
        };

        var result = filled(32, 0xAA);
        var call = wrapper.unwrapAsync(wrapped, result);
        assertTrue(arrived.await(10, TimeUnit.SECONDS));
        call.cancel(true);

        assertTrue(call.isCancelled());
        assertTrue(eventually(() -> ArrayUtility.isNullOrEmpty(result)));
        Thread.sleep(300);
        assertEquals(2, vault.requests().size());
    }

    @Test
    void cancellingTheFuture_WhileTheTokenSourceIsWaitedFor_CancelsTheSourcesFuture() throws Exception {
        var tokens = new FakeTokenSource();
        tokens.next = call -> new CompletableFuture<>();
        var wrapper = createWith(tokens);

        var call = wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]);
        assertTrue(eventually(() -> tokens.lastReturned != null));
        call.cancel(true);

        assertTrue(eventually(() -> tokens.lastReturned.isCancelled()));
        assertEquals(List.of(), vault.requests());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "hvs.with space", "hvs.é", "hvs.\n", "hvs.tab\t"})
    void aTokenThatIsNotOne_FailsWithoutARequest(String token) {
        var wrapper = createWith(FakeTokenSource.giving(token));

        assertFailsWith(IllegalStateException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(List.of(), vault.requests());
    }

    @Test
    void aTokenOverTheLimit_FailsWithoutARequest_AndTheLongestIsSentWhole() {
        var tooLong = createWith(FakeTokenSource.giving("t".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_TOKEN_LENGTH + 1)));
        assertFailsWith(IllegalStateException.class, tooLong.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        assertEquals(List.of(), vault.requests());

        var longest = "t".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_TOKEN_LENGTH);
        var wrapper = createWith(FakeTokenSource.giving(longest));
        assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        assertEquals(longest, vault.requests().getFirst().token());
    }

    @Test
    void aTokenSourceThatReturnsNoFutureOrNoLength_FailsWithoutARequest() {
        var noFuture = createWith(destination -> null);
        assertFailsWith(IllegalStateException.class, noFuture.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        var noLength = createWith(destination -> CompletableFuture.completedFuture(null));
        assertFailsWith(IllegalStateException.class, noLength.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        var negative = createWith(destination -> CompletableFuture.completedFuture(-1));
        assertFailsWith(IllegalStateException.class, negative.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(List.of(), vault.requests());
    }

    @Test
    void aTokenSourcesFailure_PropagatesAsItIs_AndIsNotRetried() {
        var tokens = new FakeTokenSource();
        var failure = new IllegalStateException("The login endpoint is unreachable.");
        tokens.next = call -> CompletableFuture.failedFuture(failure);
        var wrapper = createWith(tokens);

        assertSame(failure, assertFailsWith(IllegalStateException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES])));

        assertEquals(1, tokens.calls());
        assertEquals(List.of(), vault.requests());
    }

    @Test
    void aTokenSourceThatThrows_PropagatesAsItIs() {
        var wrapper = createWith(destination -> {
            throw new IllegalArgumentException("Misconfigured.");
        });

        assertFailsWith(IllegalArgumentException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        assertEquals(List.of(), vault.requests());
    }

    @Test
    void aTokenSourcesCheckedIOException_PropagatesAsUncheckedIOException() {
        var tokens = new FakeTokenSource();
        tokens.next = call -> CompletableFuture.failedFuture(new IOException("The token file can't be read."));
        var wrapper = createWith(tokens);

        var e = assertFailsWith(UncheckedIOException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("The token file can't be read.", e.getCause().getMessage());
        assertEquals(List.of(), vault.requests());
    }

    @Test
    void aTokenSourceSlowerThanTheTimeout_IsCancelled() {
        var tokens = new FakeTokenSource();
        tokens.next = call -> new CompletableFuture<>();
        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, tokens, null, options -> options.timeout(Duration.ofMillis(100)));

        assertFailsWith(CancellationException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(tokens.lastReturned.isCancelled());
        assertTrue(isZero(tokens.destinations().getFirst()));
        assertEquals(List.of(), vault.requests());
    }

    @Test
    void everyCall_AsksTheSourceForTheToken_SoATokenItReplacesIsUsed() {
        var tokens = new FakeTokenSource();
        tokens.next = call -> CompletableFuture.completedFuture(call == 1 ? "hvs.expired" : FakeTransit.TOKEN);
        var wrapper = createWith(tokens);

        assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        generate(wrapper);

        assertEquals(2, tokens.calls());
        assertEquals(List.of("hvs.expired", FakeTransit.TOKEN), vault.requests().stream().map(FakeTransit.TransitRequest::token).toList());
    }

    // --- StaticVaultTokenSource ------------------------------------------------------------------

    @Test
    void staticVaultTokenSource_SuppliesItsToken_UntilClosed() {
        var tokens = new StaticVaultTokenSource(FakeTransit.TOKEN);
        var wrapper = createWith(tokens);

        generate(wrapper);
        tokens.close();

        assertFailsWith(IllegalStateException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        assertEquals(1, vault.requests().size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "hvs.with space", "hvs.é", "hvs.line\nbreak"})
    void staticVaultTokenSource_RejectsATokenThatIsNotOne(String token) {
        assertThrows(IllegalArgumentException.class, () -> new StaticVaultTokenSource(token));
    }

    @Test
    void staticVaultTokenSource_RejectsATokenOverTheLimit_ADestinationTooSmall_AndNulls() {
        assertThrows(IllegalArgumentException.class,
                () -> new StaticVaultTokenSource("t".repeat(HashiCorpVaultTransitKeyWrapperImpl.MAX_TOKEN_LENGTH + 1)));
        assertThrows(NullPointerException.class, () -> new StaticVaultTokenSource(null));

        try (var tokens = new StaticVaultTokenSource(java.nio.CharBuffer.wrap(FakeTransit.TOKEN.toCharArray()))) {
            assertThrows(IllegalArgumentException.class, () -> tokens.copyTokenAsync(new char[4]));
            assertThrows(NullPointerException.class, () -> tokens.copyTokenAsync(null));

            var destination = new char[64];
            assertEquals(FakeTransit.TOKEN.length(), await(tokens.copyTokenAsync(destination)));
            assertEquals(FakeTransit.TOKEN, new String(destination, 0, FakeTransit.TOKEN.length()));
        }
    }

    // --- Addresses, paths and redirects ----------------------------------------------------------

    @Test
    void theNamespaceMountAndPathPrefix_AreUsed() {
        var prefixed = track(new FakeTransit("transit/team-a", "/vault"));
        var wrapper = create(prefixed.address(), KEY_NAME, null, new FakeTokenSource(), null,
                options -> options.mountPath("transit/team-a").namespace("team-a/prod"));

        generate(wrapper);

        assertEquals(1, prefixed.requests().size());
        assertEquals("team-a/prod", prefixed.requests().getFirst().namespace());
        assertEquals(List.of(), prefixed.unexpectedRequests());
    }

    @Test
    void anAddressWithoutATrailingSlash_IsCalledTheSame() {
        var address = vault.address().toString();
        var wrapper = create(URI.create(address.substring(0, address.length() - 1)), KEY_NAME, null, new FakeTokenSource(), null, options -> {
        });

        generate(wrapper);

        assertEquals(1, vault.requests().size());
        assertEquals(List.of(), vault.unexpectedRequests());
    }

    @Test
    void aRedirect_IsNotFollowed() {
        vault.addKey("elsewhere");
        vault.answer = (request, count) -> request.key().equals(KEY_NAME)
                ? new Answer(307, "", Map.of("Location", vault.transitUri("datakey/wrapped/elsewhere").toString()))
                : null;
        var wrapper = create(null);

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(307, assertInstanceOf(VaultRequestException.class, e.getCause()).statusCode());
        assertEquals(List.of(KEY_NAME), vault.requests().stream().map(FakeTransit.TransitRequest::key).toList());
    }

    @Test
    void withAllowRedirects_AClientThatFollowsThem_ResendsTheBodyAndTokenAlongTheRedirect() {
        var client = track(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build());
        vault.addKey("elsewhere");
        vault.answer = (request, count) -> request.key().equals(KEY_NAME)
                ? new Answer(307, "", Map.of("Location", vault.transitUri("encrypt/elsewhere").toString()))
                : null;
        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, new FakeTokenSource(), null, options -> options.httpClient(client).allowRedirects(true));
        var dek = random(32);

        wrap(wrapper, dek);

        // What allowRedirects means: the redirect target saw the body and the token too.
        var requests = vault.requests();
        assertEquals(List.of(KEY_NAME, "elsewhere"), requests.stream().map(FakeTransit.TransitRequest::key).toList());
        assertArrayEquals(requests.get(0).body(), requests.get(1).body());
        assertEquals(base64(dek), requests.get(1).field("plaintext"));
        assertEquals(FakeTransit.TOKEN, requests.get(1).token());
    }

    // --- Lifetime and concurrency ----------------------------------------------------------------

    @Test
    void close_LeavesASuppliedClientUsable() {
        var client = track(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
        create(vault.address(), KEY_NAME, null, new FakeTokenSource(), null, options -> options.httpClient(client)).close();

        var again = create(vault.address(), KEY_NAME, null, new FakeTokenSource(), null, options -> options.httpClient(client));
        generate(again);
    }

    @Test
    void afterClose_ACallFails_WithoutCallingVault() {
        var wrapper = create(null);
        wrapper.close();

        assertFailsWith(IllegalStateException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        assertEquals(List.of(), vault.requests());
    }

    @Test
    void theWrapper_IsSafeForConcurrentUse() {
        var wrapper = create();
        var deks = IntStream.range(0, 32).mapToObj(i -> random(32)).toList();

        var wraps = deks.stream().map(dek -> {
            var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
            return wrapper.wrapAsync(dek, wrapped).thenApply(length -> Arrays.copyOf(wrapped, length));
        }).toList();
        var reveals = new ArrayList<CompletableFuture<byte[]>>();
        for (var wrap : wraps) {
            var wrapped = await(wrap);
            var revealed = new byte[32];
            reveals.add(wrapper.unwrapAsync(wrapped, revealed).thenApply(length -> revealed));
        }

        for (var i = 0; i < deks.size(); i++)
            assertArrayEquals(deks.get(i), await(reveals.get(i)));
    }

    // --- Static helpers --------------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "vault:v1:AAAA|true",
            "vault:v1234567890:AB+/=|true",
            "vault:v1:|false",
            "vault:v:AAAA|false",
            "vault:v1AAAA|false",
            "vault:v12345678901:AAAA|false",
            "vault:v1:AA-A|false",
            "vault:|false",
            "VAULT:v1:AAAA|false",
    })
    void isVaultCiphertext_AcceptsOnlyVaultsFormat(String value, boolean expected) {
        var bytes = ascii(value);
        assertEquals(expected, HashiCorpVaultTransitKeyWrapperImpl.isVaultCiphertext(bytes, bytes.length));
        assertFalse(HashiCorpVaultTransitKeyWrapperImpl.isVaultCiphertext(new byte[0], 0));
    }

    @ParameterizedTest
    @CsvSource({
            "200, 0, 0, 200",
            "200, 1, 0, 400",
            "200, 2, 50, 850",
            "200, 5, 0, 6400",
            "200, 6, 0, 10000",
            "200, 20, 0, 10000",
            "200, 20, 100, 10100",
            "0, 3, 37, 37",
            "10000, 40, 0, 10000",
    })
    void retryDelay_DoublesUpToTheLimit_PlusJitter(int baseMillis, int retry, int jitter, int expectedMillis) {
        assertEquals(Duration.ofMillis(expectedMillis), HashiCorpVaultTransitKeyWrapperImpl.retryDelay(Duration.ofMillis(baseMillis), retry, jitter));
    }

    // --- End to end ------------------------------------------------------------------------------

    @Test
    void aCryptoProvider_GeneratesAndRevealsItsDekThroughVault() {
        var wrapper = create(null);
        try (var provider = await(new AesGcmCryptoProviderFactoryImpl().createEphemeralAsync(wrapper, 60))) {
            var expected = "hello, vault".getBytes(StandardCharsets.UTF_8);
            // Encrypt zeroes the plaintext it is given, so it gets a copy.
            var plaintext = expected.clone();
            var encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            int encryptedLength = provider.encrypt(plaintext, encrypted);
            var decrypted = new byte[provider.getDecryptedAllocationLength(encryptedLength)];
            int decryptedLength = provider.decrypt(Arrays.copyOf(encrypted, encryptedLength), decrypted);

            assertArrayEquals(expected, Arrays.copyOf(decrypted, decryptedLength));
        }
    }

    // --- Key files -------------------------------------------------------------------------------

    @Test
    void readKeyFile_ByDefault_RefusesAFileTheCurrentUserCouldHaveReplaced() throws IOException {
        // The user's temp folder (Windows) or the shared /tmp (Linux): neither is somewhere only
        // administrators can write.
        var temp = System.getProperty("java.io.tmpdir");
        Assumptions.assumeFalse(isMac() && temp.startsWith("/var/folders/"),
                "macOS's per-user temp folder is private to its user; TrustedKeyFileTest covers macOS.");

        var wrapper = create();
        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), ascii("vault:v1:AAAA"));
        try {
            assertFailsWith(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    void readKeyFile_WithANullTrust_TrustsAdministratorsOnly() throws IOException {
        // The same refusal as the shorter constructors': null is ADMINISTRATORS_ONLY, never "anyone".
        var temp = System.getProperty("java.io.tmpdir");
        Assumptions.assumeFalse(isMac() && temp.startsWith("/var/folders/"), "macOS's per-user temp folder is private to its user.");

        var wrapper = new HashiCorpVaultTransitKeyWrapperImpl(vault.address(), KEY_NAME, new FakeTokenSource(), null, null);
        track(wrapper);
        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), ascii("vault:v1:AAAA"));
        try {
            var exception = assertFailsWith(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
            assertSame(AccessDeniedException.class, exception.getClass());
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readKeyFile_Windows_WithTheWritersAccountTrusted_ReadsTheFile_AndItReveals() throws IOException {
        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, new FakeTokenSource(),
                KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(WindowsTempDirectory.currentUserSid()), options -> {
                });
        try (var dir = new WindowsTempDirectory()) {
            var wrapped = generate(wrapper);
            var path = dir.write("v1.key", wrapped);

            var read = await(wrapper.readKeyFileAsync(path));
            assertArrayEquals(wrapped, read);
            assertEquals(32, await(wrapper.unwrapAsync(read, new byte[32])));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readKeyFile_Windows_TrustingEveryone_IsRefused() throws IOException {
        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, new FakeTokenSource(),
                KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals("S-1-1-0"), options -> {
                });
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", ascii("vault:v1:AAAA"));

            assertFailsWith(IllegalArgumentException.class, wrapper.readKeyFileAsync(path));
        }
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readKeyFile_Unix_AFileOnlyItsTrustedOwnerCanReplace_IsRead_AndItReveals() throws IOException {
        // A private directory in the user's home: trusted all the way up when the home directory and
        // everything above it are, which the assumption checks.
        var uid = currentUnixUserId();
        var trust = KeyFileTrust.ADMINISTRATORS_ONLY.withUnixUserIds(uid);
        var home = Path.of(System.getProperty("user.home"));
        Assumptions.assumeTrue(isPrivateUnixPath(home, uid), "The home directory, or a directory above it, can be written by others.");

        var wrapper = create(vault.address(), KEY_NAME, CONTEXT, new FakeTokenSource(), trust, options -> {
        });
        var dir = Files.createTempDirectory(home, "hkdfguard-keys-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            var wrapped = generate(wrapper);
            var path = Files.write(dir.resolve("v1.key"), wrapped);
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));

            var read = await(wrapper.readKeyFileAsync(path));
            assertArrayEquals(wrapped, read);
            assertEquals(32, await(wrapper.unwrapAsync(read, new byte[32])));
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readKeyFile_Unix_AFileItsOwnersAccountIsNotTrustedFor_IsRefused() throws IOException {
        Assumptions.assumeFalse(currentUnixUserId() == 0, "Running as root, whose files are trusted.");

        var wrapper = create();
        var dir = Files.createDirectory(Path.of("target", "keys-" + UUID.randomUUID()).toAbsolutePath());
        try {
            var path = Files.write(dir.resolve("v1.key"), ascii("vault:v1:AAAA"));

            assertFailsWith(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
        } finally {
            deleteRecursively(dir);
        }
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private static boolean isMac() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("mac");
    }

    private static long currentUnixUserId() throws IOException {
        var probe = Path.of("target", "hkdfguard.uid.probe-" + UUID.randomUUID()).toAbsolutePath();
        Files.write(probe, new byte[0]);
        try {
            // Just created by this process, so owned by its effective user.
            return ((Number) Files.getAttribute(probe, "unix:uid")).longValue();
        } finally {
            Files.delete(probe);
        }
    }

    // Whether directory and every directory above it is owned by root or uid and writable by neither
    // group nor others.
    private static boolean isPrivateUnixPath(Path directory, long uid) throws IOException {
        for (var item = directory.toRealPath(); item != null; item = item.getParent()) {
            var owner = ((Number) Files.getAttribute(item, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue();
            var mode = ((Number) Files.getAttribute(item, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
            if ((owner != 0 && owner != uid) || (mode & 0022) != 0)
                return false;
        }
        return true;
    }

    private static void deleteRecursively(Path dir) throws IOException {
        try (var paths = Files.walk(dir)) {
            for (var item : paths.sorted(java.util.Comparator.reverseOrder()).toList())
                Files.deleteIfExists(item);
        }
    }

    private static boolean eventually(java.util.function.BooleanSupplier condition) {
        var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean())
                return true;
            sleepQuietly(10);
        }
        return condition.getAsBoolean();
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
