package io.github.runsecure.hkdfguard.options.certificate;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.security.auth.DestroyFailedException;

/**
 * A PKCS#8 private key from a PEM file: "ENCRYPTED PRIVATE KEY", decrypted with its password through
 * the JDK's PBES2 cipher - PBKDF2 with HMAC-SHA224/256/384/512, then AES-128 or AES-256 in CBC mode,
 * what OpenSSL 3 and .NET write - or, only when no password is given, a plain "PRIVATE KEY". Any
 * other scheme the file names (PBES1, the PKCS#12 PBE schemes, DES, RC2, RC4, PBKDF2 with HMAC-SHA1)
 * is refused before the password is used, as is an iteration count over
 * {@link #MAX_ITERATIONS}, so a hostile file can't make startup derive a key for hours. The file
 * is read as bytes, never as a String, and every buffer that held the decrypted key is zeroed: the
 * DER, and the PBE key the password derived. The JDK's own copies - inside the PKCS8EncodedKeySpec,
 * and the key object itself - can't be.
 */
final class PemKeys {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ENCRYPTED = "ENCRYPTED PRIVATE KEY";
    private static final String PLAIN = "PRIVATE KEY";
    private static final String PBES2_OID = "1.2.840.113549.1.5.13";

    /** The most PBKDF2 iterations accepted: far above what OpenSSL (2048) and .NET write. */
    static final int MAX_ITERATIONS = 10_000_000;

    // The JDK's names for the PBES2 schemes accepted: PBKDF2 with an HMAC-SHA2, then AES.
    private static final Pattern ALLOWED_PBES2 = Pattern.compile("PBEWithHmacSHA(224|256|384|512)AndAES_(128|256)");

    private static final String REENCRYPT = "re-encrypt it with openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256";

    // The PKCS#8 algorithms the JDK has a KeyFactory for, by OID.
    private static final Map<String, String> KEY_ALGORITHMS = Map.of(
            "1.2.840.113549.1.1.1", "RSA",
            "1.2.840.113549.1.1.10", "RSASSA-PSS",
            "1.2.840.10045.2.1", "EC",
            "1.3.101.112", "Ed25519",
            "1.3.101.113", "Ed448",
            "1.2.840.10040.4.1", "DSA");

    private PemKeys() {
    }

    /**
     * The private key in {@code pem}.
     *
     * @param pem      the file's bytes; the caller zeroes them
     * @param password the key's password, or {@code null} for a plain key
     * @param path     the file, for messages
     * @throws CryptographicException it holds no such key, the password is wrong, or the key isn't one the JDK reads
     */
    static PrivateKey read(byte[] pem, char[] password, String path) {
        var label = password == null ? PLAIN : ENCRYPTED;
        var der = block(pem, label);
        if (der == null) {
            var other = password == null ? ENCRYPTED : PLAIN;
            if (block(pem, other) != null)
                throw new CryptographicException(password == null
                        ? "The key in '" + path + "' is encrypted, but no File.PasswordSecretName names its password."
                        : "The key in '" + path + "' isn't encrypted, but File.PasswordSecretName names a password: encrypt it as PKCS#8 "
                                + "(openssl pkcs8 -topk8 -v2 aes-256-cbc), or unset the password and set File.AllowUnprotectedPrivateKey.");
            throw new CryptographicException("'" + path + "' holds no PEM \"" + label + "\" block: the key must be PKCS#8"
                    + (password == null ? "" : ", encrypted") + " (convert a PKCS#1 or SEC1 key with openssl pkcs8 -topk8).");
        }

        byte[] pkcs8 = null;
        try {
            pkcs8 = password == null ? der : decrypt(der, password, path);
            return generate(pkcs8, path);
        } finally {
            ArrayUtility.zeroMemory(der);
            ArrayUtility.zeroMemory(pkcs8);
        }
    }

    /**
     * Whether {@code key} is the private half of {@code publicKey}: the same modulus and exponent for
     * RSA, else a signature it makes that the public key verifies.
     */
    static boolean matches(PrivateKey key, PublicKey publicKey) {
        if (key instanceof RSAPrivateCrtKey rsa)
            return publicKey instanceof RSAPublicKey pub && rsa.getModulus().equals(pub.getModulus()) && rsa.getPublicExponent().equals(pub.getPublicExponent());

        var algorithm = switch (key.getAlgorithm()) {
            case "EC" -> "SHA256withECDSA";
            case "EdDSA", "Ed25519", "Ed448" -> key.getAlgorithm();
            case "DSA" -> "SHA256withDSA";
            default -> throw new CryptographicException("A " + key.getAlgorithm() + " key can't be checked against its certificate.");
        };
        try {
            var challenge = new byte[32];
            RANDOM.nextBytes(challenge);
            var signer = Signature.getInstance(algorithm);
            signer.initSign(key);
            signer.update(challenge);
            var signature = signer.sign();
            var verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    // The DER of the first PEM block with label, or null if there is none. Searched as bytes, so the
    // file never becomes a String.
    private static byte[] block(byte[] pem, String label) {
        var begin = ("-----BEGIN " + label + "-----").getBytes(StandardCharsets.US_ASCII);
        var end = ("-----END " + label + "-----").getBytes(StandardCharsets.US_ASCII);
        var start = indexOf(pem, begin, 0);
        if (start < 0)
            return null;
        var bodyStart = start + begin.length;
        var bodyEnd = indexOf(pem, end, bodyStart);
        if (bodyEnd < 0)
            return null;
        try {
            var decoded = Base64.getMimeDecoder().decode(ByteBuffer.wrap(pem, bodyStart, bodyEnd - bodyStart));
            var der = new byte[decoded.remaining()];
            decoded.get(der);
            if (decoded.hasArray())
                ArrayUtility.zeroMemory(decoded.array());
            return der;
        } catch (IllegalArgumentException e) {
            throw new CryptographicException("A PEM \"" + label + "\" block isn't valid Base64.", e);
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (var i = from; i <= haystack.length - needle.length; i++) {
            for (var j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j])
                    continue outer;
            }
            return i;
        }
        return -1;
    }

    private static byte[] decrypt(byte[] der, char[] password, String path) {
        EncryptedPrivateKeyInfo info;
        try {
            info = new EncryptedPrivateKeyInfo(der);
        } catch (IOException e) {
            throw new CryptographicException("The key in '" + path + "' isn't an encrypted PKCS#8 key.", e);
        }

        // PBES2 names its key derivation and cipher in its parameters: the JDK's cipher name for them
        // ("PBEWithHmacSHA256AndAES_256") is the parameters' toString.
        // Some JDKs name a PBES2 scheme by its OID or "PBES2", others already by the cipher name.
        var algorithm = info.getAlgName();
        var parameters = info.getAlgParameters();
        if (parameters != null && (PBES2_OID.equals(algorithm) || "PBES2".equalsIgnoreCase(algorithm)))
            algorithm = parameters.toString();
        if (parameters == null || !ALLOWED_PBES2.matcher(algorithm).matches())
            throw new CryptographicException("The key in '" + path + "' is encrypted with " + algorithm + ", which isn't accepted (PBKDF2 with"
                    + " HMAC-SHA224/256/384/512 and AES-128 or AES-256 is): " + REENCRYPT + ".");
        int iterations;
        try {
            iterations = parameters.getParameterSpec(PBEParameterSpec.class).getIterationCount();
        } catch (GeneralSecurityException e) {
            throw new CryptographicException("The key in '" + path + "' has PBES2 parameters the JDK can't read.", e);
        }
        if (iterations < 1 || iterations > MAX_ITERATIONS)
            throw new CryptographicException("The key in '" + path + "' asks for " + iterations + " PBKDF2 iterations; 1-" + MAX_ITERATIONS
                    + " are accepted: " + REENCRYPT + ".");

        var spec = new PBEKeySpec(password);
        javax.crypto.SecretKey key = null;
        try {
            key = SecretKeyFactory.getInstance(algorithm).generateSecret(spec);
            var cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, parameters);
            return cipher.doFinal(info.getEncryptedData());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new CryptographicException("The key in '" + path + "' is encrypted with " + algorithm + ", which the JDK doesn't have.", e);
        } catch (GeneralSecurityException e) {
            throw new CryptographicException("The key in '" + path + "' couldn't be decrypted: its password is wrong, or the file is damaged.", e);
        } finally {
            spec.clearPassword();
            if (key != null && !key.isDestroyed()) {
                try {
                    key.destroy();
                } catch (DestroyFailedException e) {
                    // A provider whose PBE key can't be destroyed: nothing more to do.
                }
            }
        }
    }

    private static PrivateKey generate(byte[] pkcs8, String path) {
        String oid;
        try {
            // PrivateKeyInfo ::= SEQUENCE { version INTEGER, privateKeyAlgorithm AlgorithmIdentifier, privateKey OCTET STRING, ... }
            var info = Der.parse(pkcs8).children();
            oid = oidToString(info.get(1).children().get(0));
        } catch (RuntimeException e) {
            throw new CryptographicException("The key in '" + path + "' couldn't be decrypted: its password is wrong, or it isn't a PKCS#8 key.", e);
        }
        var algorithm = KEY_ALGORITHMS.get(oid);
        if (algorithm == null)
            throw new CryptographicException("The key in '" + path + "' is a " + oid + " key, which isn't RSA, EC, EdDSA or DSA.");
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (GeneralSecurityException e) {
            throw new CryptographicException("The key in '" + path + "' isn't a valid " + algorithm + " key.", e);
        }
    }

    private static String oidToString(Der.Value value) {
        if (value.tag() != Der.OBJECT_IDENTIFIER || value.length() == 0)
            throw new IllegalArgumentException("Not an OBJECT IDENTIFIER.");
        var bytes = value.contents();
        var text = new StringBuilder();
        long component = 0;
        var first = true;
        for (var b : bytes) {
            component = (component << 7) | (b & 0x7F);
            if ((b & 0x80) != 0)
                continue;
            if (first) {
                var top = component < 40 ? 0 : component < 80 ? 1 : 2;
                text.append(top).append('.').append(component - 40L * top);
                first = false;
            } else {
                text.append('.').append(component);
            }
            component = 0;
        }
        return text.toString();
    }
}
