package io.github.runsecure.hkdfguard.keywrapping.googlekms;

import com.google.cloud.kms.v1.CryptoKeyName;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;

/**
 * The real Cloud KMS key the integration tests run against, if one was given. A test that makes
 * real Cloud KMS calls calls {@link #assumeKeyName()} first, so it is reported as skipped unless
 * {@link #KEY_NAME_VARIABLE} names a key. Once it does, a failing call - or a value that isn't a
 * key's resource name - is a test failure, never a silent pass.
 * <p>
 * It is read from the environment, else from {@link #SETTINGS_FILE} at the repository root - this
 * repository's counterpart of hkdfguard-dotnet's google.runsettings: a local file, ignored by git,
 * so the key needn't be set for every command. It names the key only; Application Default
 * Credentials sign in with gcloud auth application-default login, so no credential ever goes in it.
 */
final class GoogleKmsTestEnvironment {
    static final String KEY_NAME_VARIABLE = "HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME";
    static final String SETTINGS_FILE = "google.test.properties";

    private GoogleKmsTestEnvironment() {
    }

    /** The configured key's resource name; skips the calling test when there is none. */
    static String assumeKeyName() {
        var keyName = read(KEY_NAME_VARIABLE, settings());
        Assumptions.assumeTrue(keyName != null, "Set " + KEY_NAME_VARIABLE + " to a symmetric Cloud KMS key, in the environment or "
                + SETTINGS_FILE + ", to run Cloud KMS integration tests.");

        // A value that isn't a key's resource name (a placeholder left in place, say) fails with a
        // message naming the variable, rather than as an argument error from the wrapper.
        if (keyName.contains("[") || !CryptoKeyName.isParsableFrom(keyName))
            throw new IllegalStateException(KEY_NAME_VARIABLE + " is '" + keyName + "', which isn't a key's resource name. Replace the "
                    + "placeholders in " + SETTINGS_FILE + " (docs/how-to/run-google-kms-integration-tests.md, step 5).");
        return keyName;
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
