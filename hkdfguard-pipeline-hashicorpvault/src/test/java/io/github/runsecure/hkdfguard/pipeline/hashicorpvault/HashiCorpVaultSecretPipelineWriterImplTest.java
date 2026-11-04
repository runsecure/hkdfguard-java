package io.github.runsecure.hkdfguard.pipeline.hashicorpvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.StaticVaultTokenSource;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultHttp;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultRequestException;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultTokenSource;
import io.github.runsecure.hkdfguard.pipeline.contract.SecretPipelineWriterContractTest;
import io.github.runsecure.hkdfguard.pipeline.hashicorpvault.FakeVault.Answer;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** The writer's contract, and what only it does, with its real HttpClient against a fake Vault on loopback. */
class HashiCorpVaultSecretPipelineWriterImplTest extends SecretPipelineWriterContractTest {
    private final FakeVault vault = new FakeVault();
    private final StaticVaultTokenSource token = new StaticVaultTokenSource(FakeVault.TOKEN);

    @AfterEach
    void closeVault() {
        token.close();
        vault.close();
    }

    // No key ring anywhere: the token is a plain source, and the only key is the protector's.
    @Override
    protected SecretPipelineWriter createWriter(PipelineDataProtector protector, List<String> secretNames) {
        return create(protector, secretNames, null);
    }

    // A name without a key reads the default key, "value".
    @Override
    protected void setText(String name, String text) {
        vault.set(name, text);
    }

    @Override
    protected void setKeys(String name, String json) {
        vault.setRawData(name, json);
    }

    @Override
    protected void failReads() {
        vault.answer = new Answer(403, "{\"errors\":[\"permission denied\"]}");
    }

    @Override
    protected Class<? extends Throwable> readFailure() {
        return VaultRequestException.class;
    }

    @Override
    protected List<String> reads() {
        return vault.reads();
    }

    private HashiCorpVaultSecretPipelineWriterImpl create(PipelineDataProtector protector, List<String> secretNames,
            HashiCorpVaultPipelineOptions options) {
        return new HashiCorpVaultSecretPipelineWriterImpl(vault.address(), token, protector, secretNames,
                options != null ? options : HashiCorpVaultPipelineOptions.builder().retryDelay(Duration.ZERO).build());
    }

    @Test
    void everyRead_SendsTheTokenAndVaultsHeaders() {
        vault.setData("myapp/db", Map.of("username", "app"));
        try (var writer = create(protector, List.of("myapp/db#username"), null)) {
            pull(writer);

            assertEquals("app", decrypt(writer.getProtectedSecrets().get("myapp__db__username"), "myapp__db__username"));
            assertEquals(List.of(FakeVault.TOKEN), vault.tokens());
            assertEquals(List.of("true"), vault.vaultRequestHeaders());
            assertEquals(List.of("(none)"), vault.namespaces());
            assertTrue(vault.unexpectedRequests().isEmpty());
        }
    }

    @Test
    void aNamespace_IsSentWithEveryRead() {
        vault.set("item", "s3cret");
        try (var writer = create(protector, List.of("item"), HashiCorpVaultPipelineOptions.builder().namespace("team-a/prod").build())) {
            pull(writer);

            assertEquals(List.of("team-a/prod"), vault.namespaces());
        }
    }

    @Test
    void aDeletedLatestVersion_OrABodyWithoutData_IsMissing() {
        vault.setDeleted("gone");
        try (var writer = create(protector, List.of("gone"), null)) {
            assertPullFails(NoSuchElementException.class, writer);

            vault.answer = new Answer(200, "{\"data\":{\"metadata\":{\"version\":3}}}");
            var e = assertPullFails(NoSuchElementException.class, writer);
            assertTrue(e.getMessage().contains("gone"));
        }
    }

    @Test
    void theDefaultKey_IsTheOptionsOne() {
        vault.setData("myapp/db", Map.of("password", "s3cret"));
        try (var writer = create(protector, List.of("myapp/db"), HashiCorpVaultPipelineOptions.builder().defaultKey("password").build())) {
            pull(writer);

            assertEquals("s3cret", decrypt(writer.getProtectedSecrets().get("myapp__db"), "myapp__db"));
        }
    }

    @Test
    void kvVersion1_IsReadAtTheMountPath() {
        try (var v1 = new FakeVault("kv", VaultKvVersion.V1, "");
                var writer = new HashiCorpVaultSecretPipelineWriterImpl(v1.address(), token, protector, List.of("item"),
                        HashiCorpVaultPipelineOptions.builder().kvVersion(VaultKvVersion.V1).mountPath("kv").build())) {
            v1.set("item", "s3cret");

            pull(writer);

            assertEquals("s3cret", decrypt(writer.getProtectedSecrets().get("item"), "item"));
            assertTrue(v1.unexpectedRequests().isEmpty());
        }
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "403 | {\"errors\":[\"permission denied\"]}         | 403 Forbidden: permission denied",
            "404 | {\"errors\":[\"no handler for route \\\"secret/data/item\\\"\"]} | 404 Not Found: no handler for route",
            "404 | <html>Not Found</html>                       | 404 Not Found",
            "500 | ''                                           | 500 Internal Server Error",
            "502 | <html>Bad Gateway</html>                     | 502 Bad Gateway"})
    void aVaultError_Propagates_WithItsStatusAndErrors(int status, String body, String detail) {
        vault.answer = new Answer(status, body);
        try (var writer = create(protector, List.of("item"), null)) {
            var e = assertPullFails(VaultRequestException.class, writer);

            assertEquals(status, e.statusCode());
            assertTrue(e.getMessage().startsWith("Vault refused to read 'item': " + detail), e.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"[]", "", "{\"data\":"})
    void aSuccessThatIsntVaultsJson_IsRefused(String body) {
        vault.answer = new Answer(200, body);
        try (var writer = create(protector, List.of("item"), null)) {
            assertPullFails(InvalidSecretDataException.class, writer);
            assertTrue(writer.getProtectedSecrets().isEmpty());
        }
    }

    @Test
    void aTokenSourceSupplyingNoToken_FailsThePull() {
        VaultTokenSource empty = destination -> CompletableFuture.completedFuture(0);
        try (var writer = new HashiCorpVaultSecretPipelineWriterImpl(vault.address(), empty, protector, List.of("item"), null)) {
            assertPullFails(IllegalStateException.class, writer);
            assertTrue(vault.reads().isEmpty());
        }
    }

    @Test
    void aClosedWriter_ReadsNothing() {
        var writer = create(protector, List.of("item"), null);
        writer.close();

        assertPullFails(IllegalStateException.class, writer);
        assertTrue(vault.reads().isEmpty());
    }

    @Test
    void theListIsCopied() {
        vault.set("item", "s3cret");
        var names = new ArrayList<>(List.of("item"));
        try (var writer = create(protector, names, null)) {
            names.add("other");

            pull(writer);

            assertEquals(List.of("item"), List.copyOf(writer.getProtectedSecrets().keySet()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ConnectionStrings:Admin", "../escape", ".hidden"})
    void aNameThatIsntAPath_IsRefused(String secretName) {
        assertThrows(IllegalArgumentException.class, () -> create(protector, List.of(secretName), null));
    }

    @Test
    void aPathLongerThanVaultReads_IsRefused() {
        assertTrue(HashiCorpVaultSecretPipelineWriterImpl.isValidSecretName("a".repeat(HashiCorpVaultSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(HashiCorpVaultSecretPipelineWriterImpl.isValidSecretName("a".repeat(HashiCorpVaultSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(HashiCorpVaultSecretPipelineWriterImpl.isValidSecretName(null));
    }

    @Test
    void constructor_ChecksTheAddressTokenSourceAndOptions() {
        assertThrows(NullPointerException.class,
                () -> new HashiCorpVaultSecretPipelineWriterImpl(vault.address(), null, protector, List.of("item"), null));
        assertThrows(IllegalArgumentException.class,
                () -> new HashiCorpVaultSecretPipelineWriterImpl(URI.create("http://vault.example.com"), token, protector, List.of("item"), null));
        assertThrows(IllegalArgumentException.class,
                () -> create(protector, List.of("item"), HashiCorpVaultPipelineOptions.builder().defaultKey("").build()));
        assertThrows(IllegalArgumentException.class,
                () -> create(protector, List.of("item"), HashiCorpVaultPipelineOptions.builder().mountPath("../sys").build()));
        assertThrows(IllegalArgumentException.class,
                () -> create(protector, List.of("item"), HashiCorpVaultPipelineOptions.builder().timeout(Duration.ZERO).build()));
        assertThrows(NullPointerException.class, () -> HashiCorpVaultPipelineOptions.builder().kvVersion(null));
        assertEquals(VaultHttp.MAX_RETRY_DELAY, HashiCorpVaultPipelineOptions.MAX_RETRY_DELAY);

        try (var defaults = new HashiCorpVaultSecretPipelineWriterImpl(vault.address(), token, protector, List.of("item"), null)) {
            assertTrue(defaults.getProtectedSecrets().isEmpty());
        }
    }
}
