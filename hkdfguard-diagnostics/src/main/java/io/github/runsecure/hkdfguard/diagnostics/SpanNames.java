package io.github.runsecure.hkdfguard.diagnostics;

/**
 * Span/operation names, one nested class per component - lowercase, dot-separated
 * (OpenTelemetry semantic-convention style: {@code hkdfguard.<component>.<operation>}), identical
 * to the .NET library's ActivityNames, so every port's spans query the same way.
 */
public final class SpanNames {
    private SpanNames() {
    }

    public static final class Cache {
        public static final String ADD = "hkdfguard.cache.add";
        public static final String ADD_OR_UPDATE = "hkdfguard.cache.add_or_update";
        public static final String DECRYPT = "hkdfguard.cache.decrypt";
        public static final String POPULATE = "hkdfguard.cache.populate";

        private Cache() {
        }
    }

    public static final class DataProtection {
        public static final String PROTECTOR_ENCRYPT = "hkdfguard.data_protection.protector.encrypt";
        public static final String PROTECTOR_DECRYPT = "hkdfguard.data_protection.protector.decrypt";
        public static final String KEY_WRAPPED_KEY_ENCRYPT = "hkdfguard.data_protection.key_wrapped_key.encrypt";
        public static final String KEY_WRAPPED_KEY_DECRYPT = "hkdfguard.data_protection.key_wrapped_key.decrypt";
        public static final String EPHEMERAL_KEY_INITIALIZE = "hkdfguard.data_protection.ephemeral_key.initialize";
        public static final String KEY_RING_ADD = "hkdfguard.data_protection.key_ring.add";
        public static final String KEY_RING_GET = "hkdfguard.data_protection.key_ring.get";
        public static final String KEY_RING_GET_CURRENT = "hkdfguard.data_protection.key_ring.get_current";
        public static final String KEY_RING_ROTATE_EPHEMERAL = "hkdfguard.data_protection.key_ring.rotate_ephemeral";
        public static final String FORMAT_PROVIDER_FORMAT = "hkdfguard.data_protection.format.format";
        public static final String FORMAT_PROVIDER_PARSE = "hkdfguard.data_protection.format.parse";
        public static final String FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH = "hkdfguard.data_protection.format.get_max_decrypted_length";

        private DataProtection() {
        }
    }

    public static final class CryptoProviderAesGcm256 {
        public static final String ENCRYPT = "hkdfguard.crypto_provider_aes_gcm256.encrypt";
        public static final String DECRYPT = "hkdfguard.crypto_provider_aes_gcm256.decrypt";
        public static final String BACKGROUND_REFRESH = "hkdfguard.crypto_provider_aes_gcm256.background_refresh";

        private CryptoProviderAesGcm256() {
        }
    }

    public static final class EncryptedConfiguration {
        public static final String DECRYPT = "hkdfguard.encrypted_configuration.decrypt";

        private EncryptedConfiguration() {
        }
    }
}
