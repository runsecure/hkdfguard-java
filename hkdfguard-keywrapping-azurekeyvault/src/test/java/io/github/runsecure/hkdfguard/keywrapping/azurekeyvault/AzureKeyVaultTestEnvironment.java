package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;

/**
 * The real Key Vault keys the integration tests run against, if they were given. A test that makes
 * real Azure Key Vault calls calls {@link #assumeKeys()} first, so it is reported as skipped unless
 * both {@link #WRAPPING_KEY_VARIABLE} and {@link #SIGNING_KEY_VARIABLE} are set. Once they are, a
 * failing call - or a value that isn't a key identifier - is a test failure, never a silent pass.
 * <p>
 * Each is read from the environment, else from {@link #SETTINGS_FILE} at the repository root - this
 * repository's counterpart of hkdfguard-dotnet's azure.runsettings: a local file, ignored by git, so
 * the keys needn't be set for every command. It names keys only; DefaultAzureCredential signs in
 * with az login, so no credential ever goes in it.
 */
final class AzureKeyVaultTestEnvironment {
    static final String WRAPPING_KEY_VARIABLE = "HKDFGUARD_TEST_AZURE_WRAP_KEY_ID";
    static final String SIGNING_KEY_VARIABLE = "HKDFGUARD_TEST_AZURE_SIGN_KEY_ID";
    static final String SETTINGS_FILE = "azure.test.properties";

    /** The configured wrapping and signing key identifiers. */
    record Keys(String wrappingKeyId, String signingKeyId) {
    }

    private AzureKeyVaultTestEnvironment() {
    }

    /** The configured keys; skips the calling test unless both are set. */
    static Keys assumeKeys() {
        var settings = settings();
        var wrappingKeyId = read(WRAPPING_KEY_VARIABLE, settings);
        var signingKeyId = read(SIGNING_KEY_VARIABLE, settings);
        Assumptions.assumeTrue(wrappingKeyId != null && signingKeyId != null, "Set " + WRAPPING_KEY_VARIABLE + " to an RSA key and "
                + SIGNING_KEY_VARIABLE + " to an EC P-256 key, in the environment or " + SETTINGS_FILE
                + ", to run Azure Key Vault integration tests.");
        return new Keys(checked(WRAPPING_KEY_VARIABLE, wrappingKeyId), checked(SIGNING_KEY_VARIABLE, signingKeyId));
    }

    // A value that isn't a key identifier (a placeholder left in place, say) fails with a message
    // naming the variable, rather than as an argument error from the wrapper.
    private static String checked(String variable, String value) {
        try {
            KeyVaultKeyId.parse(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(variable + " is '" + value + "', which isn't a key identifier. See "
                    + "docs/how-to/run-azure-key-vault-integration-tests.md.", e);
        }
        return value;
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
