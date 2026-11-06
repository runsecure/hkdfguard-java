package io.github.runsecure.hkdfguard.options.certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;

class LoadedCertificateTest {
    private static LoadedCertificate loaded(KeyPair key) {
        var certificate = TestCertificates.selfSigned(key, "CN=localhost", Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
        return new LoadedCertificate(certificate, List.of(certificate), key.getPrivate());
    }

    private static SSLContext trusting(X509Certificate certificate) throws Exception {
        var trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("server", certificate);
        var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        var context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        return context;
    }

    // A real handshake on the loopback: the server presents the loaded certificate through its key manager.
    static void handshake(LoadedCertificate server, String protocol) throws Exception {
        var context = server.createSslContext();
        try (var listener = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            listener.setSoTimeout(10_000);
            var accepted = CompletableFuture.runAsync(() -> {
                try (var socket = (SSLSocket) listener.accept()) {
                    socket.setEnabledProtocols(new String[] { protocol });
                    socket.startHandshake();
                    socket.getOutputStream().write(42);
                    socket.getOutputStream().flush();
                } catch (IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
            });
            try (var client = (SSLSocket) trusting(server.getCertificate()).getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), listener.getLocalPort())) {
                client.setSoTimeout(10_000);
                client.setEnabledProtocols(new String[] { protocol });
                client.startHandshake();
                assertEquals(42, client.getInputStream().read());
                assertEquals(server.getCertificate(), client.getSession().getPeerCertificates()[0]);
            }
            accepted.get(10, TimeUnit.SECONDS);
        }
    }

    @Test
    void itsKeyManager_PresentsItOverTls_ForRsaAndEcKeys() throws Exception {
        for (var key : List.of(TestCertificates.rsa(), TestCertificates.ec())) {
            try (var certificate = loaded(key)) {
                handshake(certificate, "TLSv1.3");
                handshake(certificate, "TLSv1.2");
            }
        }
    }

    @Test
    void itsKeyManager_PresentsOnlyTheKeyTypeItHas() {
        try (var certificate = loaded(TestCertificates.ec())) {
            var manager = certificate.createKeyManager();
            assertEquals("hkdfguard", manager.chooseServerAlias("EC", null, null));
            assertNull(manager.chooseServerAlias("RSA", null, null));
            assertEquals("hkdfguard", manager.chooseClientAlias(new String[] { "RSA", "EC" }, null, null));
            assertNull(manager.chooseEngineClientAlias(new String[] { "RSA" }, null, null));
            assertArrayEquals(new String[] { "hkdfguard" }, manager.getServerAliases("EC", null));
            assertNull(manager.getClientAliases("RSA", null));
            assertNull(manager.getPrivateKey("another"));
            assertEquals(certificate.getCertificate(), manager.getCertificateChain("hkdfguard")[0]);
        }
    }

    @Test
    void closing_DropsTheKey_AndTheKeyManagerPresentsNothing() {
        var certificate = loaded(TestCertificates.ec());
        var manager = certificate.createKeyManager();

        certificate.close();
        certificate.close();

        assertTrue(certificate.isClosed());
        assertThrows(IllegalStateException.class, certificate::getCertificate);
        assertThrows(IllegalStateException.class, certificate::getPrivateKey);
        assertThrows(IllegalStateException.class, certificate::getCertificateChain);
        assertThrows(IllegalStateException.class, certificate::hasPrivateKey);
        assertThrows(IllegalStateException.class, certificate::createKeyManager);
        assertNull(manager.chooseServerAlias("EC", null, null));
        assertNull(manager.getPrivateKey("hkdfguard"));
        assertNull(manager.getCertificateChain("hkdfguard"));
    }

    @Test
    void closing_DestroysAKeyThatCanBeDestroyed() {
        var key = TestCertificates.ec();
        var destroyable = new DestroyableKey(key.getPrivate());
        var certificate = new LoadedCertificate(TestCertificates.selfSigned(key, "CN=x", Instant.now(), Instant.now().plusSeconds(60)), null, destroyable);

        certificate.close();

        assertTrue(destroyable.isDestroyed());
    }

    @Test
    void aCertificateWithoutItsKey_HasNothingToPresent() {
        var key = TestCertificates.ec();
        var certificate = TestCertificates.selfSigned(key, "CN=x", Instant.now(), Instant.now().plusSeconds(60));
        try (var loaded = new LoadedCertificate(certificate, List.of(), null)) {
            assertEquals(List.of(certificate), loaded.getCertificateChain());
            assertThrows(IllegalStateException.class, loaded::createKeyManager);
            assertThrows(IllegalStateException.class, loaded::createSslContext);
        }
    }

    private static final class DestroyableKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private final transient PrivateKey key;
        private boolean destroyed;

        DestroyableKey(PrivateKey key) {
            this.key = key;
        }

        @Override
        public String getAlgorithm() {
            return key.getAlgorithm();
        }

        @Override
        public String getFormat() {
            return key.getFormat();
        }

        @Override
        public byte[] getEncoded() {
            return key.getEncoded();
        }

        @Override
        public void destroy() {
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }
}
