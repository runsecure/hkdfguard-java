package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.time.Duration;

/**
 * A token bucket, as Go's rate.Limiter: up to {@link #burst()} requests at once, then
 * {@link #requestsPerSecond()}. A request waits for its turn rather than failing. Thread-safe;
 * several clients may share one.
 */
public final class VaultRateLimiter {
    private final double requestsPerSecond;
    private final int burst;
    private double tokens;
    private long updated;

    /**
     * @param requestsPerSecond how many requests a second, once the burst is spent; may be fractional
     * @param burst             how many requests may go at once
     * @throws IllegalArgumentException requestsPerSecond isn't a positive number, or burst isn't positive
     */
    public VaultRateLimiter(double requestsPerSecond, int burst) {
        if (!Double.isFinite(requestsPerSecond) || requestsPerSecond <= 0)
            throw new IllegalArgumentException("The rate must be a positive number; it is " + requestsPerSecond + ".");
        if (burst < 1)
            throw new IllegalArgumentException("The burst must be at least 1; it is " + burst + ".");

        this.requestsPerSecond = requestsPerSecond;
        this.burst = burst;
        this.tokens = burst;
        this.updated = System.nanoTime();
    }

    /** Requests a second, once the burst is spent. */
    public double requestsPerSecond() {
        return requestsPerSecond;
    }

    /** Requests that may go at once. */
    public int burst() {
        return burst;
    }

    /**
     * Waits until a request may be sent, and counts it - unless the wait would take longer than
     * maxWaitNanos, when it returns false at once without counting it.
     *
     * @throws InterruptedException interrupted while waiting; the turn is given back
     */
    boolean acquire(long maxWaitNanos) throws InterruptedException {
        long waitNanos;
        synchronized (this) {
            var now = System.nanoTime();
            tokens = Math.min(burst, tokens + (now - updated) / 1e9 * requestsPerSecond);
            updated = now;

            var wait = tokens >= 1 ? 0 : (1 - tokens) / requestsPerSecond * 1e9;
            if (wait > maxWaitNanos)
                return false;

            // Reserved now, waited for after: a request behind it waits for its own turn as well.
            tokens--;
            waitNanos = (long) Math.ceil(wait);
        }

        if (waitNanos <= 0)
            return true;

        try {
            Thread.sleep(Duration.ofNanos(waitNanos));
            return true;
        } catch (InterruptedException e) {
            // The request won't be sent: give its turn back.
            synchronized (this) {
                tokens = Math.min(burst, tokens + 1);
            }
            throw e;
        }
    }
}
