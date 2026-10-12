package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * A pipeline protects configuration under a fresh key; once that key is wrapped and registered in a
 * ring at the pipeline's version, a protector for the configuration key's purpose reads the values
 * back - exactly what an application's configuration reader does.
 */
class PipelineInteropTest {
    private static final String ID = "Pipeline:Secret";
    private static final int VERSION = 3;

    // The ring the application builds once the pipeline's key is wrapped and registered.
    private static KeyRingImpl ringHolding(byte[] key) {
        var ring = new KeyRingImpl(new DefaultFormatProviderImpl());
        ring.add(VERSION, new DataEncryptionKeyImpl(await(AesGcmCryptoProviderImpl.createAsync(new TestKeys.FakeKeyWrapper(key), new byte[] {1}, 60))));
        return ring;
    }

    private static String decrypt(DataProtector protector, String formatted) {
        var result = new char[protector.getMaxDecryptedLength(formatted)];
        return new String(result, 0, protector.decrypt(formatted, result));
    }

    @Test
    void pipelineValues_DecryptThroughAKeyRingProtectorForTheIdentifiersPurpose() {
        try (var pipeline = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), VERSION)) {
            var formatted = pipeline.encrypt("hello", ID);
            var key = Base64.getDecoder().decode(pipeline.getKeyAsBase64().toString());

            try (var ring = ringHolding(key)) {
                assertEquals("hello", decrypt(ring.createProtector(ProtectedConfigurationPurpose.forKey(ID)), formatted));
                // Case-insensitive like configuration keys.
                assertEquals("hello", decrypt(ring.createProtector(ProtectedConfigurationPurpose.forKey(ID.toUpperCase())), formatted));
            }
        }
    }

    @Test
    void pipelineValues_DoNotDecryptUnderAPlainPurposeOfTheSameName_OrAnotherKey() {
        try (var pipeline = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), VERSION)) {
            var formatted = pipeline.encrypt("hello", ID);
            var key = Base64.getDecoder().decode(pipeline.getKeyAsBase64().toString());

            try (var ring = ringHolding(key)) {
                assertThrows(AuthenticationTagMismatchException.class, () -> ring.createProtector(ID).decrypt(formatted, new char[16]));
                assertThrows(AuthenticationTagMismatchException.class,
                        () -> ring.createProtector(ProtectedConfigurationPurpose.forKey("Pipeline:Other")).decrypt(formatted, new char[16]));
            }
        }
    }

    @Test
    void keyRingValues_ForTheIdentifiersPurpose_DecryptThroughThePipelineProtectorsKey() {
        // The reverse direction: what a ring protector writes under the purpose, the pipeline's key
        // and identifier read - checked here through a second ring holding the same key.
        try (var pipeline = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), VERSION)) {
            var key = Base64.getDecoder().decode(pipeline.getKeyAsBase64().toString());
            try (var ring = ringHolding(key)) {
                var formatted = ring.createProtector(ProtectedConfigurationPurpose.forKey(ID)).encrypt("hello");
                var result = new char[16];

                assertEquals("hello", new String(result, 0, pipeline.decrypt(formatted, ID, result)));
            }
        }
    }
}
