package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultConnectionOptions;

/**
 * Which transit secrets engine a {@link HashiCorpVaultTransitKeyWrapperImpl} calls, and how it
 * connects. Immutable: build one with {@link #builder()}. The values are checked by the wrapper's
 * constructor, not here, so an options object can be built up in any order.
 * <p>
 * Every transit call the wrapper makes is safe to repeat, so {@link #retryCount()} applies to all
 * of them; a 400 for a ciphertext that doesn't authenticate isn't retried. An encrypt request's body
 * holds the DEK, so an {@link #httpClient()} that follows redirects would send the DEK along too.
 * {@link #tls()} takes PEM, or password-protected key stores whose passwords are protected by a
 * protector on the key ring.
 */
public final class HashiCorpVaultTransitKeyWrapperOptions extends VaultConnectionOptions {
    private final String mountPath;

    private HashiCorpVaultTransitKeyWrapperOptions(Builder builder) {
        super(builder);
        mountPath = builder.mountPath;
    }

    /** A builder holding the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** A builder holding these options, to change some of them. */
    public Builder toBuilder() {
        return copyConnectionTo(new Builder()).mountPath(mountPath);
    }

    /** Where the transit secrets engine is mounted, e.g. "transit" (the default) or "transit/team-a". */
    public String mountPath() {
        return mountPath;
    }

    /** Builds a {@link HashiCorpVaultTransitKeyWrapperOptions}; every value starts at its default. */
    public static final class Builder extends VaultConnectionOptions.Builder<Builder> {
        private String mountPath = "transit";

        private Builder() {
        }

        @Override
        protected Builder self() {
            return this;
        }

        /** See {@link HashiCorpVaultTransitKeyWrapperOptions#mountPath()}. */
        public Builder mountPath(String mountPath) {
            this.mountPath = mountPath;
            return this;
        }

        public HashiCorpVaultTransitKeyWrapperOptions build() {
            return new HashiCorpVaultTransitKeyWrapperOptions(this);
        }
    }
}
