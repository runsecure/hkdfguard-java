package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import org.junit.jupiter.api.Assumptions;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProviderChain;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.profiles.ProfileFile;
import software.amazon.awssdk.profiles.ProfileFileLocation;

/**
 * The real secret the integration tests read, if one was given. A test that makes real AWS Secrets
 * Manager calls calls {@link #assumeSecretName()} first, so it is reported as skipped unless
 * {@link #SECRET_NAME_VARIABLE} names a secret. Once it does, a failing call is a test failure,
 * never a silent pass.
 * <p>
 * It is read from the environment, else from {@link #SETTINGS_FILE} at the repository root: a
 * local file, ignored by git, so the name needn't be set for every command. It names the secret
 * only, so no credential ever goes in it: credentials come from {@link #credentials()}, and the
 * region from the SDK's default chain.
 */
final class AwsSecretsManagerTestEnvironment {
    static final String SECRET_NAME_VARIABLE = "HKDFGUARD_TEST_AWS_SECRET_NAME";
    static final String SETTINGS_FILE = "aws.test.properties";

    private AwsSecretsManagerTestEnvironment() {
    }

    /** The configured secret's name; skips the calling test when there is none. */
    static String assumeSecretName() {
        var name = read(SECRET_NAME_VARIABLE, settings());
        Assumptions.assumeTrue(name != null, "Set " + SECRET_NAME_VARIABLE + " to a secret's name, in the environment or "
                + SETTINGS_FILE + ", to run AWS Secrets Manager cache integration tests.");

        // A value the cache would report missing without a call (a placeholder or an ARN, say) fails
        // with a message naming the variable, rather than as a secret that isn't there.
        if (!AwsSecretsManagerSecretCacheImpl.isValidSecretName(name))
            throw new IllegalStateException(SECRET_NAME_VARIABLE + " is '" + name + "', which isn't a secret's name: 1-"
                    + AwsSecretsManagerSecretCacheImpl.MAX_SECRET_NAME_LENGTH + " ASCII letters, digits and /_+=.@- (not an ARN).");
        return name;
    }

    /**
     * The test principal's access keys: from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, else from the
     * shared credentials file's profile (AWS_PROFILE, or default) - the file aws configure writes,
     * read on its own, as the .NET tests' SDK reads it. The SDK's default chain merges the config
     * file into that profile, and a login_session there (from aws login) would take precedence over
     * its keys, running the tests as whoever signed in rather than as the test principal.
     */
    static AwsCredentialsProvider credentials() {
        var profileName = System.getenv("AWS_PROFILE");
        var credentialsFile = ProfileFile.builder()
                .content(ProfileFileLocation.credentialsFileLocation().orElseThrow(
                        () -> new IllegalStateException("There is no AWS credentials file; run aws configure, or set AWS_ACCESS_KEY_ID.")))
                .type(ProfileFile.Type.CREDENTIALS)
                .build();
        return AwsCredentialsProviderChain.of(
                EnvironmentVariableCredentialsProvider.create(),
                ProfileCredentialsProvider.builder()
                        .profileFile(credentialsFile)
                        .profileName(profileName == null || profileName.isEmpty() ? "default" : profileName)
                        .build());
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
