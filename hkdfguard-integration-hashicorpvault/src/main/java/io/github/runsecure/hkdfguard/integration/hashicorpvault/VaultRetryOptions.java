package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

/**
 * When and how often a {@link VaultClient} retries a failed request: vault-client-go's
 * RetryConfiguration (its go-retryablehttp client). Retries happen within the request's timeout,
 * and the request is sent whole each time - its body is held in memory for that. Unlike
 * go-retryablehttp, a POST, PUT or PATCH that failed without an answer is sent again only when the
 * connection was refused or never made: once sent, Vault may have applied it, and a second token or
 * write would follow. Immutable: build one with {@link #builder()}.
 */
public final class VaultRetryOptions {
    /** Whether to retry an attempt. */
    @FunctionalInterface
    public interface RetryPolicy {
        /**
         * @param statusCode the status Vault answered with; 0 if no answer came
         * @param failure    what the attempt failed with when no answer came; null otherwise
         */
        boolean shouldRetry(int statusCode, Throwable failure);
    }

    /** How long to wait before a retry. */
    @FunctionalInterface
    public interface Backoff {
        /**
         * @param min        {@link #retryWaitMin()}
         * @param max        {@link #retryWaitMax()}
         * @param attempt    the attempt that failed, 0 for the first
         * @param statusCode the status it was answered with; 0 if none
         */
        Duration delay(Duration min, Duration max, int attempt, int statusCode);
    }

    private final Duration retryWaitMin;
    private final Duration retryWaitMax;
    private final int retryMax;
    private final RetryPolicy checkRetry;
    private final Backoff backoff;

    private VaultRetryOptions(Builder builder) {
        retryWaitMin = builder.retryWaitMin;
        retryWaitMax = builder.retryWaitMax;
        retryMax = builder.retryMax;
        checkRetry = builder.checkRetry;
        backoff = builder.backoff;
    }

    /** A builder holding the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** A builder holding these options, to change some of them. */
    public Builder toBuilder() {
        return new Builder().retryWaitMin(retryWaitMin).retryWaitMax(retryWaitMax).retryMax(retryMax).checkRetry(checkRetry).backoff(backoff);
    }

    /** The least time to wait before a retry - VAULT_RETRY_WAIT_MIN. Default 1 second. */
    public Duration retryWaitMin() {
        return retryWaitMin;
    }

    /** The most time to wait before a retry - VAULT_RETRY_WAIT_MAX. Default 1.5 seconds. */
    public Duration retryWaitMax() {
        return retryWaitMax;
    }

    /** How many times to retry - VAULT_MAX_RETRIES. Zero or less for none. Default 2: three tries in all. */
    public int retryMax() {
        return retryMax;
    }

    /** Whether to retry; null for {@link #defaultRetryPolicy}. */
    public RetryPolicy checkRetry() {
        return checkRetry;
    }

    /** How long to wait before a retry; null for {@link #linearJitterBackoff}. */
    public Backoff backoff() {
        return backoff;
    }

    /**
     * go-retryablehttp's default policy, plus 412 (which Vault answers when an X-Vault-Index state
     * isn't there yet): retry when no answer came - unless the server's certificate was refused,
     * which another attempt would meet again - and on 412, 429, and any 5xx but 501.
     */
    public static boolean defaultRetryPolicy(int statusCode, Throwable failure) {
        if (failure != null)
            return !isCertificateFailure(failure);

        return statusCode == 0 || statusCode == 412 || statusCode == 429 || (statusCode >= 500 && statusCode != 501);
    }

    /**
     * go-retryablehttp's LinearJitterBackoff: a random wait between min and max, times the number of
     * attempts made so far - spread out so clients retrying together don't all arrive together.
     */
    @SuppressWarnings("java:S2245")
    public static Duration linearJitterBackoff(Duration min, Duration max, int attempt, int statusCode) {
        var attempts = attempt + 1;
        if (max.compareTo(min) <= 0)
            return min.multipliedBy(attempts);

        var jitter = ThreadLocalRandom.current().nextLong(VaultHttp.saturatedNanos(max.minus(min)));
        return min.plusNanos(jitter).multipliedBy(attempts);
    }

    private static boolean isCertificateFailure(Throwable failure) {
        for (var e = failure; e != null; e = e.getCause()) {
            if (e instanceof SSLHandshakeException || e instanceof SSLPeerUnverifiedException || e instanceof CertificateException)
                return true;
        }
        return false;
    }

    /** Builds {@link VaultRetryOptions}; every value starts at its default. */
    public static final class Builder {
        private Duration retryWaitMin = Duration.ofMillis(1000);
        private Duration retryWaitMax = Duration.ofMillis(1500);
        private int retryMax = 2;
        private RetryPolicy checkRetry;
        private Backoff backoff;

        private Builder() {
        }

        /** See {@link VaultRetryOptions#retryWaitMin()}. */
        public Builder retryWaitMin(Duration retryWaitMin) {
            this.retryWaitMin = Objects.requireNonNull(retryWaitMin, "retryWaitMin");
            return this;
        }

        /** See {@link VaultRetryOptions#retryWaitMax()}. */
        public Builder retryWaitMax(Duration retryWaitMax) {
            this.retryWaitMax = Objects.requireNonNull(retryWaitMax, "retryWaitMax");
            return this;
        }

        /** See {@link VaultRetryOptions#retryMax()}. */
        public Builder retryMax(int retryMax) {
            this.retryMax = retryMax;
            return this;
        }

        /** See {@link VaultRetryOptions#checkRetry()}; null for the default. */
        public Builder checkRetry(RetryPolicy checkRetry) {
            this.checkRetry = checkRetry;
            return this;
        }

        /** See {@link VaultRetryOptions#backoff()}; null for the default. */
        public Builder backoff(Backoff backoff) {
            this.backoff = backoff;
            return this;
        }

        public VaultRetryOptions build() {
            return new VaultRetryOptions(this);
        }
    }
}
