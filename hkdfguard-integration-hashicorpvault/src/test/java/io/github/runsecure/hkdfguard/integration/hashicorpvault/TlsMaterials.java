package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.spi.ToolProvider;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Certificates for the TLS tests, made once per run with the JDK's keytool: a CA; a server key with
 * a certificate the CA issued to vault.test and 127.0.0.1, one issued to vault.test only, and one
 * self-signed for 127.0.0.1; and an RSA client certificate the CA issued.
 */
final class TlsMaterials {
    private static final String PASSWORD = "changeit";
    private static TlsMaterials instance;

    final Path directory;
    final X509Certificate ca;
    final String caPem;
    final PrivateKey serverKey;
    final X509Certificate serverForHostAndIp;
    final X509Certificate serverForNameOnly;
    final X509Certificate serverSelfSigned;
    final PrivateKey clientKey;
    final X509Certificate client;

    static synchronized TlsMaterials get() {
        if (instance == null) {
            try {
                instance = new TlsMaterials(Files.createTempDirectory("hkdfguard-vault-tls"));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return instance;
    }

    private TlsMaterials(Path directory) {
        this.directory = directory;
        try {
            keytool("-genkeypair", "-alias", "ca", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=HkdfGuard Test CA",
                    "-ext", "bc:c", "-validity", "3", "-keystore", file("ca.p12"));
            keytool("-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=vault.test",
                    "-ext", "SAN=ip:127.0.0.1", "-validity", "3", "-keystore", file("server.p12"));
            keytool("-certreq", "-alias", "server", "-keystore", file("server.p12"), "-file", file("server.csr"));
            keytool("-gencert", "-alias", "ca", "-keystore", file("ca.p12"), "-infile", file("server.csr"), "-outfile", file("server-ip.pem"),
                    "-rfc", "-validity", "3", "-ext", "SAN=dns:vault.test,ip:127.0.0.1", "-ext", "eku=serverAuth,clientAuth");
            keytool("-gencert", "-alias", "ca", "-keystore", file("ca.p12"), "-infile", file("server.csr"), "-outfile", file("server-name.pem"),
                    "-rfc", "-validity", "3", "-ext", "SAN=dns:vault.test", "-ext", "eku=serverAuth,clientAuth");
            keytool("-genkeypair", "-alias", "client", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=hkdfguard-client",
                    "-validity", "3", "-keystore", file("client.p12"));
            keytool("-certreq", "-alias", "client", "-keystore", file("client.p12"), "-file", file("client.csr"));
            keytool("-gencert", "-alias", "ca", "-keystore", file("ca.p12"), "-infile", file("client.csr"), "-outfile", file("client.pem"),
                    "-rfc", "-validity", "3", "-ext", "eku=clientAuth");

            var caStore = load("ca.p12");
            ca = (X509Certificate) caStore.getCertificate("ca");
            caPem = pem("CERTIFICATE", ca.getEncoded());
            Files.writeString(directory.resolve("ca.pem"), caPem);

            var serverStore = load("server.p12");
            serverKey = (PrivateKey) serverStore.getKey("server", PASSWORD.toCharArray());
            serverSelfSigned = (X509Certificate) serverStore.getCertificate("server");
            serverForHostAndIp = certificate("server-ip.pem");
            serverForNameOnly = certificate("server-name.pem");

            var clientStore = load("client.p12");
            clientKey = (PrivateKey) clientStore.getKey("client", PASSWORD.toCharArray());
            client = certificate("client.pem");
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Could not make the TLS test certificates.", e);
        }
    }

    /** A server SSLContext presenting certificate (with the CA after it, unless it's self-signed); requiring a client certificate the CA issued if clientAuth. */
    SSLContext serverContext(X509Certificate certificate, boolean clientAuth) {
        try {
            var store = KeyStore.getInstance("PKCS12");
            store.load(null, null);
            Certificate[] chain = certificate == serverSelfSigned ? new Certificate[] {certificate} : new Certificate[] {certificate, ca};
            store.setKeyEntry("server", serverKey, PASSWORD.toCharArray(), chain);
            var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, PASSWORD.toCharArray());

            var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            var trusted = KeyStore.getInstance("PKCS12");
            trusted.load(null, null);
            trusted.setCertificateEntry("ca", ca);
            trust.init(trusted);

            var context = SSLContext.getInstance("TLS");
            context.init(keys.getKeyManagers(), clientAuth ? trust.getTrustManagers() : null, null);
            return context;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    Path write(String name, String content) {
        try {
            return Files.writeString(directory.resolve(name), content);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String pem(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }

    /** The PKCS#1 RSAPrivateKey a PKCS#8 RSA key wraps: its OCTET STRING's contents. */
    static byte[] pkcs1(PrivateKey rsa) {
        return Der.elements(Der.contents(rsa.getEncoded())).get(2).contents();
    }

    /** The SEC1 ECPrivateKey a PKCS#8 EC key wraps, with its curve added as [0] parameters as OpenSSL writes it. */
    static byte[] sec1WithCurve(PrivateKey ec) {
        var pkcs8 = Der.elements(Der.contents(ec.getEncoded()));
        var curve = Der.elements(pkcs8.get(1).contents()).get(1).encoded();
        var sec1 = Der.elements(Der.contents(pkcs8.get(2).contents()));
        var parts = new ArrayList<byte[]>();
        parts.add(sec1.get(0).encoded());
        parts.add(sec1.get(1).encoded());
        parts.add(Der.tlv(0xA0, curve));
        for (var i = 2; i < sec1.size(); i++) {
            if (sec1.get(i).tag() != 0xA0)
                parts.add(sec1.get(i).encoded());
        }
        return Der.tlv(0x30, concat(parts));
    }

    private static byte[] concat(List<byte[]> parts) {
        var out = new ByteArrayOutputStream();
        for (var part : parts)
            out.writeBytes(part);
        return out.toByteArray();
    }

    private X509Certificate certificate(String name) throws IOException, GeneralSecurityException {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Files.readAllBytes(directory.resolve(name))));
    }

    private KeyStore load(String name) throws IOException, GeneralSecurityException {
        var store = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(directory.resolve(name))) {
            store.load(in, PASSWORD.toCharArray());
        }
        return store;
    }

    private String file(String name) {
        return directory.resolve(name).toString();
    }

    private static void keytool(String... args) throws IOException {
        var all = new ArrayList<>(Arrays.asList(args));
        all.addAll(List.of("-storepass", PASSWORD, "-keypass", PASSWORD, "-storetype", "PKCS12", "-noprompt"));

        var tool = ToolProvider.findFirst("keytool");
        if (tool.isPresent()) {
            var output = new ByteArrayOutputStream();
            var stream = new PrintStream(output, true, StandardCharsets.UTF_8);
            if (tool.get().run(stream, stream, all.toArray(String[]::new)) != 0)
                throw new IOException("keytool " + String.join(" ", args) + " failed: " + output.toString(StandardCharsets.UTF_8));
            return;
        }

        var executable = Path.of(System.getProperty("java.home"), "bin",
                System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win") ? "keytool.exe" : "keytool");
        all.addFirst(executable.toString());
        var process = new ProcessBuilder(all).redirectErrorStream(true).start();
        var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        try {
            if (process.waitFor() != 0)
                throw new IOException("keytool " + String.join(" ", args) + " failed: " + output);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        }
    }

    /** Just enough DER to take keys apart. */
    static final class Der {
        record Element(int tag, byte[] encoded, byte[] contents) {
        }

        static byte[] contents(byte[] tlv) {
            return elements(tlv).getFirst().contents();
        }

        static List<Element> elements(byte[] der) {
            var elements = new ArrayList<Element>();
            var p = 0;
            while (p < der.length) {
                var start = p;
                var tag = der[p++] & 0xFF;
                int length = der[p++] & 0xFF;
                if (length > 0x80) {
                    var bytes = length - 0x80;
                    length = 0;
                    for (var i = 0; i < bytes; i++)
                        length = length << 8 | (der[p++] & 0xFF);
                }
                elements.add(new Element(tag, Arrays.copyOfRange(der, start, p + length), Arrays.copyOfRange(der, p, p + length)));
                p += length;
            }
            return elements;
        }

        static byte[] tlv(int tag, byte[] contents) {
            var out = new ByteArrayOutputStream();
            out.write(tag);
            var length = contents.length;
            if (length < 0x80) {
                out.write(length);
            } else if (length < 0x100) {
                out.write(0x81);
                out.write(length);
            } else {
                out.write(0x82);
                out.write(length >> 8);
                out.write(length & 0xFF);
            }
            out.writeBytes(contents);
            return out.toByteArray();
        }
    }
}
