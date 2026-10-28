package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;

/**
 * The real Vault the integration tests run against, if one was given. A test that reads a real
 * Vault calls {@link #assumeSecretName()} first, so it is reported as skipped unless
 * {@link #SECRET_NAME_VARIABLE} names a secret. Once it does, a failing read is a test failure,
 * never a silent pass.
 * <p>
 * The secret's name, Vault's address and its CA certificate are read from the environment, else
 * from {@link #SETTINGS_FILE} at the repository root - this repository's counterpart of
 * hkdfguard-dotnet's runsettings: a local file, ignored by git, so they needn't be set for every
 * command. The token is read from the environment only ({@link #TOKEN_VARIABLE}), never from a
 * file, so no credential ever goes in one.
 */
final class HashiCorpVaultTestEnvironment {
    static final String SECRET_NAME_VARIABLE = "HKDFGUARD_TEST_VAULT_SECRET_NAME";
    static final String ADDRESS_VARIABLE = "HKDFGUARD_TEST_VAULT_ADDR";
    static final String TOKEN_VARIABLE = "HKDFGUARD_TEST_VAULT_TOKEN";
    static final String CA_CERTIFICATE_VARIABLE = "HKDFGUARD_TEST_VAULT_CACERT";
    static final String SETTINGS_FILE = "vault.test.properties";

    private static final String DEFAULT_ADDRESS = "https://127.0.0.1:8200";

    private HashiCorpVaultTestEnvironment() {
    }

    /** The configured secret's path#key; skips the calling test when there is none. */
    static String assumeSecretName() {
        var secretName = read(SECRET_NAME_VARIABLE, settings());
        Assumptions.assumeTrue(secretName != null, "Set " + SECRET_NAME_VARIABLE + " to a secret's path#key (with " + ADDRESS_VARIABLE
                + " and " + TOKEN_VARIABLE + "), in the environment or " + SETTINGS_FILE + ", to run Vault cache integration tests.");
        return secretName;
    }

    /** Vault's address; https://127.0.0.1:8200 when none is configured. */
    static URI address() {
        var address = read(ADDRESS_VARIABLE, settings());
        return URI.create(address != null ? address : DEFAULT_ADDRESS);
    }

    /** The CA certificate file Vault's server certificate is trusted through, or null to trust the JDK's default trust store. */
    static Path caCertificate() {
        var path = read(CA_CERTIFICATE_VARIABLE, settings());
        return path != null ? Path.of(path) : null;
    }

    /**
     * The token, from the environment alone.
     *
     * @throws IllegalStateException it isn't set
     */
    static String token() {
        var token = System.getenv(TOKEN_VARIABLE);
        if (token == null || token.isEmpty())
            throw new IllegalStateException("Set " + TOKEN_VARIABLE + " in the environment (never in " + SETTINGS_FILE
                    + ") to a token allowed to read " + SECRET_NAME_VARIABLE + ".");
        return token;
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
