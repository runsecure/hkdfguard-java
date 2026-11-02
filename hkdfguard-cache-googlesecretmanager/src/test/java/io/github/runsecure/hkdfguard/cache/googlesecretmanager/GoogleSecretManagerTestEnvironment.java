package io.github.runsecure.hkdfguard.cache.googlesecretmanager;

import com.google.cloud.secretmanager.v1.SecretName;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;

/**
 * The real secret the integration tests read, if one was given. A test that makes real Secret
 * Manager calls calls {@link #assumeSecretName()} first, so it is reported as skipped unless
 * {@link #SECRET_NAME_VARIABLE} names a secret. Once it does, a failing call - or a value that isn't
 * a secret's resource name - is a test failure, never a silent pass.
 * <p>
 * It is read from the environment, else from {@link #SETTINGS_FILE} at the repository root - this
 * repository's counterpart of hkdfguard-dotnet's google.runsettings: a local file, ignored by git,
 * so the secret needn't be set for every command. It names the secret only; Application Default
 * Credentials sign in with gcloud auth application-default login, so no credential ever goes in it.
 */
final class GoogleSecretManagerTestEnvironment {
    static final String SECRET_NAME_VARIABLE = "HKDFGUARD_TEST_GOOGLE_SECRET_NAME";
    static final String SETTINGS_FILE = "google.test.properties";

    private GoogleSecretManagerTestEnvironment() {
    }

    /** The configured secret: projects/{project}/secrets/{secret}; skips the calling test when there is none. */
    static SecretName assumeSecretName() {
        var secretName = read(SECRET_NAME_VARIABLE, settings());
        Assumptions.assumeTrue(secretName != null, "Set " + SECRET_NAME_VARIABLE + " to a secret's resource name "
                + "(projects/{project}/secrets/{secret}), in the environment or " + SETTINGS_FILE
                + ", to run Google Secret Manager cache integration tests.");

        // A value that isn't a secret's resource name (a placeholder left in place, say) fails with a
        // message naming the variable, rather than as an argument error from the cache.
        if (secretName.contains("[") || secretName.contains("{") || !SecretName.isParsableFrom(secretName))
            throw new IllegalStateException(SECRET_NAME_VARIABLE + " is '" + secretName + "', which isn't a secret's resource name: "
                    + "projects/{project}/secrets/{secret}. Replace the placeholders in " + SETTINGS_FILE + ".");
        return SecretName.parse(secretName);
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
