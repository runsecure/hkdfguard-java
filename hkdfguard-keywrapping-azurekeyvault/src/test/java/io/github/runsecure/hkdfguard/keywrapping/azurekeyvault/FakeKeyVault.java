package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.azure.security.keyvault.keys.cryptography.models.VerifyResult;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * An in-memory Key Vault: named RSA and EC P-256 keys, each with versions, doing real RSA-OAEP-256
 * and ES256 so wrapped DEKs and signatures behave as Key Vault's do. {@link #client} gives the
 * wrapper's seam over it; {@link KeyVaultHttpStub} serves the same keys to the real Azure clients.
 * Every seam call is recorded, and any operation can be made to fail.
 * <p>
 * Each seam call completes its future before returning, unless {@link #deferred} is set: then it is
 * answered on another thread a little later, as a real client would, after the call has returned.
 */
final class FakeKeyVault {
    static final String VAULT = "https://hkdfguard-test.vault.azure.net";
    static final String WRAPPING_KEY_NAME = "hkdfguard-wrap";
    static final String SIGNING_KEY_NAME = "hkdfguard-sign";
    static final String WRAPPING_KEY_ID = VAULT + "/keys/" + WRAPPING_KEY_NAME;
    static final String SIGNING_KEY_ID = VAULT + "/keys/" + SIGNING_KEY_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final OAEPParameterSpec OAEP_SHA256 = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

    private record Version(String version, KeyPair keyPair) {
    }

    private final Map<String, List<Version>> keys = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    /** Every seam call, as "operation key-id". */
    final List<String> calls = new CopyOnWriteArrayList<>();

    /** Makes the named seam operation ("wrap", "unwrap", "sign", "verify") throw. */
    final Map<String, RuntimeException> failures = new ConcurrentHashMap<>();

    /** Every future a seam call returned, to check a cancellation reached it. */
    final List<CompletableFuture<?>> futures = new CopyOnWriteArrayList<>();

    /** Answer each seam call on another thread, after it has returned. */
    volatile boolean deferred;

    /** Rewrites what an operation reports as the key it used. */
    volatile UnaryOperator<String> reportedKeyId;

    /** Rewrites a signature before it is returned. */
    volatile UnaryOperator<byte[]> signatureOverride;

    /** The last plaintext wrap was given: a copy as received, and the array itself, which the wrapper zeroes later. */
    volatile byte[] lastWrapped;
    volatile byte[] lastWrappedArray;

    FakeKeyVault() {
        addVersion(WRAPPING_KEY_NAME, rsa(2048));
        addVersion(SIGNING_KEY_NAME, p256());
    }

    static KeyPair rsa(int bits) {
        return generate("RSA", generator -> generator.initialize(bits, RANDOM));
    }

    static KeyPair p256() {
        return generate("EC", generator -> {
            try {
                generator.initialize(new ECGenParameterSpec("secp256r1"), RANDOM);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        });
    }

    synchronized String addVersion(String name, KeyPair keyPair) {
        var version = HexFormat.of().formatHex(randomBytes(16));
        keys.computeIfAbsent(name, n -> new ArrayList<>()).add(new Version(version, keyPair));
        return version;
    }

    synchronized String currentVersion(String name) {
        return keys.get(name).getLast().version();
    }

    /** Purges one version of a key, as deleting it from the vault would. */
    synchronized void purge(String name, String version) {
        keys.get(name).removeIf(v -> v.version().equals(version));
    }

    synchronized RSAPublicKey publicWrappingKey() {
        return (RSAPublicKey) keys.get(WRAPPING_KEY_NAME).getLast().keyPair().getPublic();
    }

    /** A key and the identifier of the version it resolved to - what Key Vault reports. */
    record Resolved(String keyId, KeyPair keyPair) {
    }

    /** The version a key identifier names, or the key's current one; a 404 refusal if there is none. */
    synchronized Resolved resolve(String keyId) {
        var id = KeyVaultKeyId.parse(keyId);
        var versions = keys.get(id.name());
        var match = versions == null ? null
                : id.version() == null ? versions.getLast()
                : versions.stream().filter(v -> v.version().equals(id.version())).findFirst().orElse(null);
        if (match == null)
            throw refusal(404, "KeyNotFound");

        var resolved = VAULT + "/keys/" + id.name() + "/" + match.version();
        var report = reportedKeyId;
        return new Resolved(report != null ? report.apply(resolved) : resolved, match.keyPair());
    }

    /** The wrapper's seam over one key identifier in this vault. */
    KeyVaultKeyClient client(String keyId) {
        return new KeyVaultKeyClient() {
            @Override
            public CompletableFuture<WrapResult> wrapKey(KeyWrapAlgorithm algorithm, byte[] key) {
                return answer("wrap", keyId, () -> {
                    requireAlgorithm(KeyWrapAlgorithm.RSA_OAEP_256, algorithm);
                    lastWrapped = key.clone();
                    lastWrappedArray = key;
                    var resolved = resolve(keyId);
                    return new WrapResult(rsaOaep(Cipher.ENCRYPT_MODE, resolved, key), algorithm, resolved.keyId());
                });
            }

            @Override
            public CompletableFuture<UnwrapResult> unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey) {
                return answer("unwrap", keyId, () -> {
                    requireAlgorithm(KeyWrapAlgorithm.RSA_OAEP_256, algorithm);
                    var resolved = resolve(keyId);
                    return new UnwrapResult(rsaOaep(Cipher.DECRYPT_MODE, resolved, encryptedKey), algorithm, resolved.keyId());
                });
            }

            @Override
            public CompletableFuture<SignResult> signData(SignatureAlgorithm algorithm, byte[] data) {
                return answer("sign", keyId, () -> {
                    requireAlgorithm(SignatureAlgorithm.ES256, algorithm);
                    var resolved = resolve(keyId);
                    return new SignResult(sign("SHA256withECDSAinP1363Format", resolved, data), algorithm, resolved.keyId());
                });
            }

            @Override
            public CompletableFuture<VerifyResult> verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature) {
                return answer("verify", keyId, () -> {
                    requireAlgorithm(SignatureAlgorithm.ES256, algorithm);
                    var resolved = resolve(keyId);
                    return new VerifyResult(verify("SHA256withECDSAinP1363Format", resolved, data, signature), algorithm, resolved.keyId());
                });
            }
        };
    }

    /** RSA-OAEP with SHA-256 and MGF1-SHA-256, as Key Vault's RSA-OAEP-256; a bad ciphertext is a 400 refusal. */
    static byte[] rsaOaep(int mode, Resolved resolved, byte[] input) {
        try {
            var cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
            cipher.init(mode, mode == Cipher.ENCRYPT_MODE ? resolved.keyPair().getPublic() : resolved.keyPair().getPrivate(), OAEP_SHA256);
            return cipher.doFinal(input);
        } catch (BadPaddingException e) {
            throw refusal(400, "BadParameter");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** An ES256 signature (r || s) of {@code data} under the resolved key, with {@code algorithm} doing the hashing or not. */
    byte[] sign(String algorithm, Resolved resolved, byte[] data) {
        try {
            var signer = Signature.getInstance(algorithm);
            signer.initSign(resolved.keyPair().getPrivate());
            signer.update(data);
            var signature = signer.sign();
            var rewrite = signatureOverride;
            return rewrite != null ? rewrite.apply(signature) : signature;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Whether {@code signature} is an ES256 signature of {@code data} under the resolved key, {@code algorithm} hashing or not. */
    static boolean verify(String algorithm, Resolved resolved, byte[] data, byte[] signature) {
        try {
            var verifier = Signature.getInstance(algorithm);
            verifier.initVerify(resolved.keyPair().getPublic());
            verifier.update(data);
            return verifier.verify(signature);
        } catch (java.security.SignatureException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A Key Vault refusal as the SDK raises it: the status, and the service's error body. */
    static HttpResponseException refusal(int status, String code) {
        var response = StubHttpResponse.error(status, code);
        var message = "Status code " + status + ", " + response.bodyText();
        return status == 404
                ? new ResourceNotFoundException(message, response, response.errorValue())
                : new HttpResponseException(message, response, response.errorValue());
    }

    private <T> CompletableFuture<T> answer(String operation, String keyId, Supplier<T> work) {
        Supplier<T> call = () -> {
            calls.add(operation + " " + keyId);
            var failure = failures.get(operation);
            if (failure != null)
                throw failure;
            return work.get();
        };

        CompletableFuture<T> future;
        if (deferred) {
            future = CompletableFuture.supplyAsync(call, CompletableFuture.delayedExecutor(50, TimeUnit.MILLISECONDS));
        } else {
            try {
                future = CompletableFuture.completedFuture(call.get());
            } catch (RuntimeException e) {
                future = CompletableFuture.failedFuture(e);
            }
        }
        futures.add(future);
        return future;
    }

    private static void requireAlgorithm(Object expected, Object actual) {
        if (!expected.equals(actual))
            throw new AssertionError("Expected " + expected + ", but the wrapper asked for " + actual + ".");
    }

    private interface Initializer {
        void initialize(KeyPairGenerator generator);
    }

    private static KeyPair generate(String algorithm, Initializer initializer) {
        try {
            var generator = KeyPairGenerator.getInstance(algorithm);
            initializer.initialize(generator);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] randomBytes(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
