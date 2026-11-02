package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import com.azure.security.keyvault.secrets.models.KeyVaultSecretIdentifier;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;

/**
 * The real Key Vault secret the integration tests read, if one was given. A test that makes real
 * Azure Key Vault calls calls {@link #assumeSecret()} first, so it is reported as skipped unless
 * {@link #SECRET_ID_VARIABLE} is set. Once it is, a failing call - or a value that isn't a secret
 * identifier - is a test failure, never a silent pass.
 * <p>
 * It is read from the environment, else from {@link #SETTINGS_FILE} at the repository root - the
 * same local file, ignored by git, that hkdfguard-keywrapping-azurekeyvault's tests read. It names a
 * secret only; DefaultAzureCredential signs in with az login, so no credential ever goes in it.
 */
final class AzureKeyVaultTestEnvironment {
    static final String SECRET_ID_VARIABLE = "HKDFGUARD_TEST_AZURE_SECRET_ID";
    static final String SETTINGS_FILE = "azure.test.properties";

    private AzureKeyVaultTestEnvironment() {
    }

    /** The configured secret, https://{vault}.vault.azure.net/secrets/{name}; skips the calling test unless it is set. */
    static KeyVaultSecretIdentifier assumeSecret() {
        var secretId = read(SECRET_ID_VARIABLE, settings());
        Assumptions.assumeTrue(secretId != null, "Set " + SECRET_ID_VARIABLE + " to a secret's identifier, in the environment or "
                + SETTINGS_FILE + ", to run Azure Key Vault secret cache integration tests.");
        try {
            return new KeyVaultSecretIdentifier(secretId);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(SECRET_ID_VARIABLE + " is '" + secretId
                    + "', which isn't a secret identifier: https://{vault}.vault.azure.net/secrets/{name}.", e);
        }
    }

    private static String read(String variable, Properties settings) {
        var value = System.getenv(variable);
        if (value == null || value.isEmpty())
            value = settings.getProperty(variable, "").strip();
        return value.isEmpty() ? null : value;
    }

    // The settings file in the nearest directory above the working directory - the module's, under
    // Surefire, or the repository's, in an IDE - that holds the Maven wrapper; empty if there is none.
    private static Properties settings() {
        var settings = new Properties();
        for (var directory = Path.of("").toAbsolutePath(); directory != null; directory = directory.getParent()) {
            if (!Files.exists(directory.resolve("mvnw")))
                continue;

            var file = directory.resolve(SETTINGS_FILE);
            if (Files.exists(file)) {
                try (var reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                    settings.load(reader);
                } catch (IOException e) {
                    throw new UncheckedIOException("Could not read " + file + ".", e);
                }
            }
            break;
        }
        return settings;
    }
}
