package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Properties;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Assumptions;

/**
 * The real Vault and transit key the integration tests run against, if one was given. A test that
 * makes real transit calls calls {@link #assumeKey()} first (or {@link #assumeOtherKey()}), so it is
 * reported as skipped unless {@link #KEY_VARIABLE} names a key. Once it does, a failing call is a
 * test failure, never a silent pass. The address, token and CA are the same variables the Vault
 * cache's integration tests read, and the same as hkdfguard-dotnet's.
 * <p>
 * Everything but the token is read from the environment, else from {@link #SETTINGS_FILE} at the
 * repository root - the file the Vault cache's integration tests read too: a local file, ignored by
 * git, so they needn't be set for every command. The token is read from the environment only
 * ({@link #TOKEN_VARIABLE}), never from a file, so no credential ever goes in one.
 */
final class VaultTransitTestEnvironment {
    static final String KEY_VARIABLE = "HKDFGUARD_TEST_VAULT_TRANSIT_KEY";
    static final String OTHER_KEY_VARIABLE = "HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY";
    static final String MOUNT_VARIABLE = "HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT";
    static final String ADDRESS_VARIABLE = "HKDFGUARD_TEST_VAULT_ADDR";
    static final String TOKEN_VARIABLE = "HKDFGUARD_TEST_VAULT_TOKEN";
    static final String CA_CERTIFICATE_VARIABLE = "HKDFGUARD_TEST_VAULT_CACERT";
    static final String SETTINGS_FILE = "vault.test.properties";

    // A dev server's, as scripts/provision-vault-transit-test-key.sh provisions it.
    private static final String DEFAULT_ADDRESS = "http://127.0.0.1:8200";

    private VaultTransitTestEnvironment() {
    }

    /** The configured transit key's name; skips the calling test when there is none. */
    static String assumeKey() {
        var key = read(KEY_VARIABLE, settings());
        Assumptions.assumeTrue(key != null, "Set " + KEY_VARIABLE + " (with " + ADDRESS_VARIABLE + " and " + TOKEN_VARIABLE
                + "), in the environment or " + SETTINGS_FILE + ", to a transit key to run Vault transit integration tests.");
        return key;
    }

    /** The second transit key's name; skips the calling test unless both keys are configured. */
    static String assumeOtherKey() {
        var settings = settings();
        var other = read(OTHER_KEY_VARIABLE, settings);
        Assumptions.assumeTrue(read(KEY_VARIABLE, settings) != null && other != null, "Set " + KEY_VARIABLE + " and " + OTHER_KEY_VARIABLE
                + " to two transit keys to check one refuses the other's DEKs.");
        return other;
    }

    /** Vault's address; http://127.0.0.1:8200 when none is configured. */
    static URI address() {
        var address = read(ADDRESS_VARIABLE, settings());
        return URI.create(address != null ? address : DEFAULT_ADDRESS);
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
                    + ") to a token allowed to use " + KEY_VARIABLE + ".");
        return token;
    }

    /**
     * The engine's mount (HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT, else "transit"), and a client trusting
     * HKDFGUARD_TEST_VAULT_CACERT, and only it, when set - otherwise the JDK's default trust store.
     * Either way the client follows no redirects. The caller closes {@code client}.
     */
    static HashiCorpVaultTransitKeyWrapperOptions options(HttpClient client) {
        var mount = read(MOUNT_VARIABLE, settings());
        return HashiCorpVaultTransitKeyWrapperOptions.builder()
                .mountPath(mount != null ? mount : "transit")
                .httpClient(client)
                .build();
    }

    /** A client trusting HKDFGUARD_TEST_VAULT_CACERT, and only it, when set; it follows no redirects. */
    static HttpClient client() {
        var builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER);
        var path = read(CA_CERTIFICATE_VARIABLE, settings());
        if (path == null)
            return builder.build();

        var caCertificate = Path.of(path);
        try (var in = Files.newInputStream(caCertificate)) {
            var trusted = KeyStore.getInstance(KeyStore.getDefaultType());
            trusted.load(null, null);
            var index = 0;
            for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(in))
                trusted.setCertificateEntry("ca-" + index++, certificate);

            var trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trusted);
            var tls = SSLContext.getInstance("TLS");
            tls.init(null, trustManagers.getTrustManagers(), null);
            return builder.sslContext(tls).build();
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + caCertificate + ".", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not trust " + caCertificate + ".", e);
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
