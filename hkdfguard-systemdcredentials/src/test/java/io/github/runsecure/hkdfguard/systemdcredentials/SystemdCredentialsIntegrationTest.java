package io.github.runsecure.hkdfguard.systemdcredentials;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The real systemd-creds: on Linux, and only when HKDFGUARD_TEST_SYSTEMD_CREDS is 1. */
class SystemdCredentialsIntegrationTest {
    @TempDir
    Path folder;

    @Test
    void aRealCredential_RoundTripsThroughSystemdCreds_AndOnlyUnderItsName() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name").startsWith("Linux") && "1".equals(System.getenv("HKDFGUARD_TEST_SYSTEMD_CREDS")),
                "Runs the real systemd-creds: set HKDFGUARD_TEST_SYSTEMD_CREDS to 1 on Linux, as root or with --user credentials.");

        var options = new SystemdCredentialsOptions();
        options.setKey(SystemdCredentialKey.HOST);
        options.setUserScope(!"root".equals(System.getProperty("user.name")));
        var credentials = new SystemdCredentials(options);
        var path = folder.resolve("tls-password.cred").toString();
        var expected = "pässwörd".getBytes(StandardCharsets.UTF_8);

        credentials.encryptAsync("tls-password", "pässwörd", path).join();
        try (var value = credentials.decryptAsync("tls-password", path).join()) {
            var bytes = new byte[value.getLength()];
            value.copyTo(bytes);
            assertArrayEquals(expected, bytes);
        }

        var encrypted = Files.readAllBytes(Path.of(path));
        for (var i = 0; i + expected.length <= encrypted.length; i++)
            assertTrue(!Arrays.equals(encrypted, i, i + expected.length, expected, 0, expected.length), "The plaintext is in the credential file.");
        var ex = assertThrows(CompletionException.class, () -> credentials.decryptAsync("db-password", path).join());
        assertInstanceOf(IllegalStateException.class, ex.getCause());
    }
}
