package io.github.runsecure.hkdfguard.pipeline.hashicorpvault;

import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultConnectionOptions;
import java.util.Objects;

/**
 * Which KV secrets engine a {@link HashiCorpVaultSecretPipelineWriterImpl} reads, and how it connects.
 * Immutable: build one with {@link #builder()}. The values are checked by the writer's constructor,
 * not here, so an options object can be built up in any order.
 * <p>
 * Give {@link #tls()} a PEM certificate and key: a password-protected key store's password must be
 * protected by a protector on a key ring, which a pipeline doesn't have yet.
 */
public final class HashiCorpVaultPipelineOptions extends VaultConnectionOptions {
    private final String mountPath;
    private final VaultKvVersion kvVersion;
    private final String defaultKey;

    private HashiCorpVaultPipelineOptions(Builder builder) {
        super(builder);
        mountPath = builder.mountPath;
        kvVersion = builder.kvVersion;
        defaultKey = builder.defaultKey;
    }

    /** A builder holding the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** A builder holding these options, to change some of them. */
    public Builder toBuilder() {
        return copyConnectionTo(new Builder())
                .mountPath(mountPath)
                .kvVersion(kvVersion)
                .defaultKey(defaultKey);
    }

    /** Where the KV secrets engine is mounted, e.g. "secret" (the default) or "kv/team-a". */
    public String mountPath() {
        return mountPath;
    }

    /** The engine's version. Default {@link VaultKvVersion#V2}. */
    public VaultKvVersion kvVersion() {
        return kvVersion;
    }

    /**
     * The key read from a secret named without one: "myapp/db" reads this key of the secret at
     * myapp/db, while "myapp/db#password" reads its password key. Default "value".
     */
    public String defaultKey() {
        return defaultKey;
    }

    /** Builds a {@link HashiCorpVaultPipelineOptions}; every value starts at its default. */
    public static final class Builder extends VaultConnectionOptions.Builder<Builder> {
        private String mountPath = "secret";
        private VaultKvVersion kvVersion = VaultKvVersion.V2;
        private String defaultKey = "value";

        private Builder() {
        }

        @Override
        protected Builder self() {
            return this;
        }

        /** See {@link HashiCorpVaultPipelineOptions#mountPath()}. */
        public Builder mountPath(String mountPath) {
            this.mountPath = mountPath;
            return this;
        }

        /**
         * See {@link HashiCorpVaultPipelineOptions#kvVersion()}.
         *
         * @throws NullPointerException kvVersion is null
         */
        public Builder kvVersion(VaultKvVersion kvVersion) {
            this.kvVersion = Objects.requireNonNull(kvVersion, "kvVersion");
            return this;
        }

        /** See {@link HashiCorpVaultPipelineOptions#defaultKey()}. */
        public Builder defaultKey(String defaultKey) {
            this.defaultKey = defaultKey;
            return this;
        }

        public HashiCorpVaultPipelineOptions build() {
            return new HashiCorpVaultPipelineOptions(this);
        }
    }
}
