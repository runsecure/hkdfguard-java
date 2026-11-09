package io.github.runsecure.hkdfguard.options.certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.x500.X500Principal;

/**
 * Self-signed certificates, PEM files and encrypted PKCS#8 keys for the tests, from the JDK alone:
 * a few lines of DER, since the JDK has no certificate builder and the project no BouncyCastle PKIX.
 */
final class TestCertificates {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] SHA256_WITH_RSA = { 0x30, 0x0D, 0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00 };
    private static final byte[] SHA256_WITH_ECDSA = { 0x30, 0x0A, 0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    private static final byte[] PBES2 = { 0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x05, 0x0D };

    private TestCertificates() {
    }

    static KeyPair rsa() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static KeyPair ec() {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static X509Certificate selfSigned(KeyPair key, String subject, Instant notBefore, Instant notAfter) {
        return selfSigned(key, new X500Principal(subject).getEncoded(), notBefore, notAfter);
    }

    /** A self-signed certificate whose subject (and issuer) is exactly the DER given. */
    static X509Certificate selfSigned(KeyPair key, byte[] subjectDer, Instant notBefore, Instant notAfter) {
        var rsa = key.getPrivate().getAlgorithm().equals("RSA");
        var algorithm = rsa ? SHA256_WITH_RSA : SHA256_WITH_ECDSA;
        var tbs = sequence(
                tlv(0xA0, tlv(0x02, new byte[] { 2 })),
                tlv(0x02, new BigInteger(64, RANDOM).add(BigInteger.ONE).toByteArray()),
                algorithm,
                subjectDer,
                sequence(time(notBefore), time(notAfter)),
                subjectDer,
                key.getPublic().getEncoded());
        try {
            var signer = Signature.getInstance(rsa ? "SHA256withRSA" : "SHA256withECDSA");
            signer.initSign(key.getPrivate());
            signer.update(tbs);
            var signature = signer.sign();
            var bitString = new byte[signature.length + 1];
            System.arraycopy(signature, 0, bitString, 1, signature.length);
            var der = sequence(tbs, algorithm, tlv(0x03, bitString));
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A Name of one attribute per RDN, each value with the string tag given: {oid bytes, tag, value} triples. */
    static byte[] name(Object... attributes) {
        var rdns = new byte[attributes.length / 3][];
        for (var i = 0; i < rdns.length; i++) {
            var oid = (byte[]) attributes[3 * i];
            var tag = (int) attributes[3 * i + 1];
            var value = (String) attributes[3 * i + 2];
            var bytes = switch (tag) {
                case 0x1E -> value.getBytes(StandardCharsets.UTF_16BE);
                case 0x13, 0x16 -> value.getBytes(StandardCharsets.US_ASCII);
                default -> value.getBytes(StandardCharsets.UTF_8);
            };
            rdns[i] = tlv(0x31, sequence(tlv(0x06, oid), tlv(tag, bytes)));
        }
        return sequence(rdns);
    }

    static final byte[] CN = { 0x55, 0x04, 0x03 };
    static final byte[] O = { 0x55, 0x04, 0x0A };
    static final byte[] DC = { 0x09, (byte) 0x92, 0x26, (byte) 0x89, (byte) 0x93, (byte) 0xF2, 0x2C, 0x64, 0x01, 0x19 };

    static String pem(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }

    static String certificatePem(X509Certificate... certificates) {
        var text = new StringBuilder();
        try {
            for (var certificate : certificates)
                text.append(pem("CERTIFICATE", certificate.getEncoded()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        return text.toString();
    }

    /** The key as an encrypted PKCS#8 PEM, under PBES2 with the JDK cipher name given ("PBEWithHmacSHA256AndAES_256"). */
    static String encryptedPbes2Pem(PrivateKey key, char[] password, String cipherName, int iterations) {
        try {
            var cipher = Cipher.getInstance(cipherName);
            var salt = new byte[16];
            var iv = new byte[16];
            RANDOM.nextBytes(salt);
            RANDOM.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyFactory.getInstance(cipherName).generateSecret(new PBEKeySpec(password)),
                    new PBEParameterSpec(salt, iterations, new IvParameterSpec(iv)));
            var encrypted = cipher.doFinal(key.getEncoded());
            // EncryptedPrivateKeyInfo can't be made from PBES2 parameters, so it is encoded here.
            var info = sequence(sequence(PBES2, cipher.getParameters().getEncoded()), tlv(0x04, encrypted));
            return pem("ENCRYPTED PRIVATE KEY", info);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * An encrypted PKCS#8 PEM naming PBES2 with cipherName and iterations, over bytes that aren't a
     * key: for a scheme or iteration count refused before anything is decrypted.
     */
    static String pbes2PemWithoutKey(String cipherName, int iterations) {
        try {
            var salt = new byte[16];
            var iv = new byte[16];
            RANDOM.nextBytes(salt);
            RANDOM.nextBytes(iv);
            var parameters = java.security.AlgorithmParameters.getInstance(cipherName);
            parameters.init(new PBEParameterSpec(salt, iterations, new IvParameterSpec(iv)));
            var info = sequence(sequence(PBES2, parameters.getEncoded()), tlv(0x04, new byte[48]));
            return pem("ENCRYPTED PRIVATE KEY", info);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The key as an encrypted PKCS#8 PEM under a PKCS#12 PBE scheme ("PBEWithSHA1AndDESede"). */
    static String encryptedPbes1Pem(PrivateKey key, char[] password, String cipherName) {
        try {
            var cipher = Cipher.getInstance(cipherName);
            var salt = new byte[8];
            RANDOM.nextBytes(salt);
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeyFactory.getInstance(cipherName).generateSecret(new PBEKeySpec(password)),
                    new PBEParameterSpec(salt, 2048));
            var info = new javax.crypto.EncryptedPrivateKeyInfo(cipher.getParameters(), cipher.doFinal(key.getEncoded()));
            return pem("ENCRYPTED PRIVATE KEY", info.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] time(Instant instant) {
        var utc = instant.atZone(ZoneOffset.UTC);
        var utcTime = utc.getYear() >= 1950 && utc.getYear() < 2050;
        var text = DateTimeFormatter.ofPattern(utcTime ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'").format(utc);
        return tlv(utcTime ? 0x17 : 0x18, text.getBytes(StandardCharsets.US_ASCII));
    }

    static byte[] sequence(byte[]... parts) {
        var out = new ByteArrayOutputStream();
        for (var part : parts)
            out.writeBytes(part);
        return tlv(0x30, out.toByteArray());
    }

    static byte[] tlv(int tag, byte[] value) {
        var out = new ByteArrayOutputStream();
        out.write(tag);
        var length = value.length;
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else if (length < 0x10000) {
            out.write(0x82);
            out.write(length >> 8);
            out.write(length & 0xFF);
        } else {
            out.write(0x83);
            out.write(length >> 16);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
        out.writeBytes(value);
        return out.toByteArray();
    }
}
