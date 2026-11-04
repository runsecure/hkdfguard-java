package io.github.runsecure.hkdfguard.options.certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Instant;
import java.util.Collections;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * The loader against the real Windows certificate store, through SunMSCAPI. The read-only test runs
 * on every Windows machine. The round trip adds a throwaway self-signed certificate and key to the
 * CurrentUser My store through KeyStore itself, and removes both afterwards, so it runs only when
 * HKDFGUARD_TEST_WINDOWS_CERTIFICATE_STORE is 1.
 */
class WindowsCertificateStoreTest {
    private static final String STORE = "Windows-MY-CURRENTUSER";

    private static void requireWindows() {
        Assumptions.assumeTrue(Platform.current() == Platform.WINDOWS, "SunMSCAPI's stores are Windows only.");
    }

    private static CertificateOptions currentUserMy(String subject) {
        var store = new CertificateStoreOptions();
        store.setStoreLocation(StoreLocation.CURRENT_USER);
        store.setSubject(subject);
        var options = new CertificateOptions();
        options.setWindows(store);
        return options;
    }

    @Test
    void theRealStore_IsOpened_AndASubjectItDoesntHave_IsReportedMissing() {
        requireWindows();
        var subject = "CN=hkdfguard-test-" + UUID.randomUUID();

        var ex = assertThrows(IllegalStateException.class, () -> new CertificateOptionsLoader().load(currentUserMy(subject)));
        assertEquals("The CurrentUser My store holds no certificate whose subject is '" + subject + "'.", ex.getMessage());

        var root = currentUserMy(subject);
        root.getWindows().setStoreLocation(StoreLocation.LOCAL_MACHINE);
        root.getWindows().setStoreName(StoreName.ROOT);
        root.setRequirePrivateKey(false);
        assertThrows(IllegalStateException.class, () -> new CertificateOptionsLoader().load(root));
    }

    @Test
    void aThrowawayCertificate_InTheRealCurrentUserMyStore_IsFound_ItsKeyAHandleInWindows() throws Exception {
        requireWindows();
        Assumptions.assumeTrue("1".equals(System.getenv("HKDFGUARD_TEST_WINDOWS_CERTIFICATE_STORE")),
                "Adds and removes a certificate in CurrentUser My: set HKDFGUARD_TEST_WINDOWS_CERTIFICATE_STORE to 1.");

        var subject = "CN=hkdfguard-test-" + UUID.randomUUID() + ", O=HkdfGuard Tests";
        var alias = "hkdfguard-test-" + UUID.randomUUID();
        var key = TestCertificates.rsa();
        var certificate = TestCertificates.selfSigned(key, subject, Instant.now().minusSeconds(300), Instant.now().plusSeconds(3600));

        var store = KeyStore.getInstance(STORE);
        store.load(null, null);
        // SunMSCAPI writes the certificate, and the key into a new key container, straight into the store.
        store.setKeyEntry(alias, key.getPrivate(), null, new X509Certificate[] { certificate });
        try {
            try (var loaded = new CertificateOptionsLoader().load(currentUserMy(subject.toLowerCase(java.util.Locale.ROOT)))) {
                assertEquals(certificate, loaded.getCertificate());

                // A handle to the key in Windows, not the key: nothing of it can be read out.
                var handle = loaded.getPrivateKey();
                assertFalse(handle instanceof RSAPrivateCrtKey, handle.getClass().getName());
                assertNull(handle.getEncoded());

                var data = "signed by Windows".getBytes(StandardCharsets.US_ASCII);
                var signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(handle);
                signer.update(data);
                var verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(certificate.getPublicKey());
                verifier.update(data);
                assertTrue(verifier.verify(signer.sign()));

                LoadedCertificateTest.handshake(loaded, "TLSv1.2");
            }
        } finally {
            var cleanup = KeyStore.getInstance(STORE);
            cleanup.load(null, null);
            for (var entry : Collections.list(cleanup.aliases())) {
                if (cleanup.getCertificate(entry) instanceof X509Certificate x && x.equals(certificate))
                    cleanup.deleteEntry(entry);
            }
        }

        var after = KeyStore.getInstance(STORE);
        after.load(null, null);
        for (var entry : Collections.list(after.aliases()))
            assertFalse(after.getCertificate(entry).equals(certificate), "The throwaway certificate is still in the store.");
    }
}
