package io.github.runsecure.hkdfguard.dataencryptionkey;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.RefreshFailurePolicy;
import io.github.runsecure.hkdfguard.abstractions.ServiceNames;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds a {@link KeyRingImpl} from wrapped-DEK files on disk and/or ephemeral keys, suitable for
 * creating once at startup and sharing. One {@link KeyWrapper} is shared by every registered key -
 * it's bound only to a KEK (e.g. a native wrapper's service name), not to any one wrapped payload,
 * so it can reveal any number of different files' DEKs. For each key file, build asks the
 * {@link CryptoProviderFactory} to create a provider bound to that file's wrapped bytes, read through
 * the key wrapper's {@link KeyWrapper#readKeyFileAsync} (so the native wrapper reads it through the
 * native library's own checks on the file and its location); for each
 * ephemeral version, to create one around a fresh DEK generated (and wrapped) at build time. Every
 * provider is wrapped in a {@link DataEncryptionKeyImpl} owned by the ring, and the key refresh
 * interval is passed to the factory as each provider's refresh interval.
 * <p>
 * Key files are rotated by deployment, not here: each release brings its own freshly generated key
 * files. Ephemeral keys are rotated here: a ring with any ephemeral key adds a fresh one as its new
 * current version every {@link #getEphemeralKeyRotationInterval()} (24 hours unless configured
 * otherwise). Rotation adds at the current version + 1, so a ring that rotates must have its
 * highest ephemeral version above every key file - otherwise the first rotation would supersede the
 * key file and new values would be encrypted under a key that does not survive a restart; build
 * refuses that layout unless rotation is turned off with {@link #withoutEphemeralKeyRotation()}.
 */
public final class KeyRingBuilder {
    /** How often a ring with ephemeral keys adds a fresh one as its current version, unless configured otherwise. */
    public static final Duration DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL = Duration.ofHours(24);

    /**
     * Shortest rotation interval {@link #withEphemeralKeyRotation} accepts. Every rotation generates
     * a key through the KEK and starts another background refresh loop, so rotating faster than
     * this buys no security and only loads the KMS.
     */
    public static final Duration MIN_EPHEMERAL_KEY_ROTATION_INTERVAL = Duration.ofHours(1);

    /** Longest rotation interval {@link #withEphemeralKeyRotation} accepts - about 49.7 days, as on every port. */
    public static final Duration MAX_EPHEMERAL_KEY_ROTATION_INTERVAL = Duration.ofMillis(0xFFFFFFFFL - 1);

    /**
     * How long a superseded ephemeral key stays in the ring for decryption, unless configured
     * otherwise: values encrypted under it remain readable for at least this long after a rotation
     * replaced it, then it is closed (zeroing its DEK) and removed.
     */
    public static final Duration DEFAULT_EPHEMERAL_KEY_RETENTION = Duration.ofHours(24);

    /** Shortest retention {@link #withEphemeralKeyRetention} accepts. */
    public static final Duration MIN_EPHEMERAL_KEY_RETENTION = Duration.ofMinutes(1);

    /**
     * The refresh-failure policy every built provider gets unless configured otherwise: fail closed
     * after this many consecutive failed refreshes. With a key refresh interval of 60 that is about
     * three minutes of KEK outage before the key is zeroed.
     */
    public static final int DEFAULT_MAX_REFRESH_FAILURES = RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES;

    private final TreeMap<Integer, Path> keyFiles = new TreeMap<>();
    private final List<Integer> ephemeralVersions = new ArrayList<>();
    private KeyWrapper keyWrapper;
    private CryptoProviderFactory cryptoProviderFactory;
    private EncryptedFormatProvider formatProvider = new DefaultFormatProviderImpl();
    private Logger logger;
    private String serviceName;
    private Integer keyRefreshInterval;
    private Integer maxRefreshFailures = DEFAULT_MAX_REFRESH_FAILURES;
    private Duration ephemeralKeyRotationInterval = DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL;
    private Duration ephemeralKeyRetention = DEFAULT_EPHEMERAL_KEY_RETENTION;

    /** A builder with nothing registered yet, and every default in place. */
    public KeyRingBuilder() {
    }

    /** The service name identifying this ring's KEK, if one was given - for callers to read back. */
    public String getServiceName() {
        return serviceName;
    }

    /** Seconds between re-reveals of each key through the KEK; null until set. */
    public Integer getKeyRefreshInterval() {
        return keyRefreshInterval;
    }

    /**
     * Consecutive failed refreshes tolerated before a provider fails closed. Defaults to
     * {@link #DEFAULT_MAX_REFRESH_FAILURES}; null only after {@link #withFailOpenOnRefreshFailure()}.
     */
    public Integer getMaxRefreshFailures() {
        return maxRefreshFailures;
    }

    /**
     * How often the built ring adds a fresh ephemeral key as its new current version. Defaults to
     * {@link #DEFAULT_EPHEMERAL_KEY_ROTATION_INTERVAL}; null only after
     * {@link #withoutEphemeralKeyRotation()}. Applies only to a ring with at least one ephemeral key.
     */
    public Duration getEphemeralKeyRotationInterval() {
        return ephemeralKeyRotationInterval;
    }

    /**
     * How long a superseded ephemeral key stays registered for decryption after a rotation replaces
     * it. Defaults to {@link #DEFAULT_EPHEMERAL_KEY_RETENTION}.
     */
    public Duration getEphemeralKeyRetention() {
        return ephemeralKeyRetention;
    }

    /**
     * Sets how often the built ring rotates its ephemeral encryption key: each interval it generates
     * a fresh ephemeral key and adds it at the current version + 1, so every later encrypt uses it.
     *
     * @throws IllegalArgumentException interval is outside {@link #MIN_EPHEMERAL_KEY_ROTATION_INTERVAL}
     *                                  to {@link #MAX_EPHEMERAL_KEY_ROTATION_INTERVAL}
     */
    public KeyRingBuilder withEphemeralKeyRotation(Duration interval) {
        Objects.requireNonNull(interval, "interval");
        if (interval.compareTo(MIN_EPHEMERAL_KEY_ROTATION_INTERVAL) < 0 || interval.compareTo(MAX_EPHEMERAL_KEY_ROTATION_INTERVAL) > 0)
            throw new IllegalArgumentException("The ephemeral key rotation interval must be between " + MIN_EPHEMERAL_KEY_ROTATION_INTERVAL
                    + " and " + MAX_EPHEMERAL_KEY_ROTATION_INTERVAL + "; it is " + interval + ".");

        ephemeralKeyRotationInterval = interval;
        return this;
    }

    /**
     * Turns scheduled ephemeral key rotation off: the ephemeral key built at startup stays current
     * until the process restarts. A later {@link #withEphemeralKeyRotation} call replaces this.
     */
    public KeyRingBuilder withoutEphemeralKeyRotation() {
        ephemeralKeyRotationInterval = null;
        return this;
    }

    /** Tests only: any positive interval, so rotation can be observed in milliseconds. */
    KeyRingBuilder withEphemeralKeyRotationForTesting(Duration interval) {
        ephemeralKeyRotationInterval = interval;
        return this;
    }

    /**
     * Sets how long a superseded ephemeral key stays registered for decryption after a rotation
     * replaces it. Once that long has passed - checked at the next rotation - the key is closed,
     * zeroing its DEK, and removed. Keys read from key files are never retired.
     *
     * @throws IllegalArgumentException retention is below {@link #MIN_EPHEMERAL_KEY_RETENTION}
     */
    public KeyRingBuilder withEphemeralKeyRetention(Duration retention) {
        Objects.requireNonNull(retention, "retention");
        if (retention.compareTo(MIN_EPHEMERAL_KEY_RETENTION) < 0)
            throw new IllegalArgumentException("The ephemeral key retention must be at least " + MIN_EPHEMERAL_KEY_RETENTION + "; it is " + retention + ".");

        ephemeralKeyRetention = retention;
        return this;
    }

    /** Tests only: any positive retention, so retirement can be observed in milliseconds. */
    KeyRingBuilder withEphemeralKeyRetentionForTesting(Duration retention) {
        ephemeralKeyRetention = retention;
        return this;
    }

    /**
     * Receives an info entry for every ephemeral key rotation and retirement and an error for every
     * failed one; null (the default) for {@link KeyRingImpl}'s own SLF4J logger.
     */
    public KeyRingBuilder withLogger(Logger logger) {
        this.logger = logger;
        return this;
    }

    /**
     * The service name identifying this ring's KEK to the native KMS library: 1-128 ASCII letters,
     * digits or '.', not starting with '.' and without "..".
     *
     * @throws NullPointerException     serviceName is null
     * @throws IllegalArgumentException serviceName breaks a {@link ServiceNames} rule
     */
    public KeyRingBuilder withServiceName(String serviceName) {
        ServiceNames.requireValid(serviceName, "serviceName");
        this.serviceName = serviceName;
        return this;
    }

    /**
     * How often, in seconds, each key is re-revealed through the KEK to confirm the KEK is still
     * available - 1-300, so a bad value fails here, not at build. A revocation check, not a limit on
     * how long the DEK stays in memory. Together with {@link #getMaxRefreshFailures()} it sets how
     * quickly a revoked KEK stops a running process.
     *
     * @throws IllegalArgumentException keyRefreshInterval is not between 1 and 300
     */
    public KeyRingBuilder withKeyRefreshInterval(int keyRefreshInterval) {
        if (keyRefreshInterval < 1 || keyRefreshInterval > 300)
            throw new IllegalArgumentException("keyRefreshInterval must be between 1 and 300 seconds; it is " + keyRefreshInterval + ".");

        this.keyRefreshInterval = keyRefreshInterval;
        return this;
    }

    /**
     * The refresh-failure policy handed to every provider build creates: after this many
     * consecutive failed attempts to re-reveal a key, that key's provider fails closed.
     *
     * @throws IllegalArgumentException maxRefreshFailures is below 1
     */
    public KeyRingBuilder withMaxRefreshFailures(int maxRefreshFailures) {
        if (maxRefreshFailures < 1)
            throw new IllegalArgumentException("maxRefreshFailures must be at least 1; it is " + maxRefreshFailures + ".");

        this.maxRefreshFailures = maxRefreshFailures;
        return this;
    }

    /**
     * Opts out of failing closed: every provider keeps using its last good key no matter how many
     * refreshes fail, so revoking or losing the KEK never stops a running process. Choose this only
     * when availability matters more than revocation taking effect, and keep the crypto provider's
     * error log visible - each failed refresh is logged, the only sign the KEK is gone.
     */
    public KeyRingBuilder withFailOpenOnRefreshFailure() {
        maxRefreshFailures = null;
        return this;
    }

    /** The key wrapper shared by every registered key. */
    public KeyRingBuilder withKeyWrapper(KeyWrapper keyWrapper) {
        this.keyWrapper = keyWrapper;
        return this;
    }

    /**
     * The factory build uses to create each key's provider - once per key file (with the shared key
     * wrapper and that file's wrapped bytes), once per ephemeral version - e.g.
     * {@code new AesGcmCryptoProviderFactoryImpl()}.
     */
    public KeyRingBuilder withCryptoProviderFactory(CryptoProviderFactory cryptoProviderFactory) {
        this.cryptoProviderFactory = cryptoProviderFactory;
        return this;
    }

    /** Overrides the format provider the built ring uses for its protectors. Defaults to {@link DefaultFormatProviderImpl}. */
    public KeyRingBuilder withFormatProvider(EncryptedFormatProvider formatProvider) {
        this.formatProvider = Objects.requireNonNull(formatProvider, "formatProvider");
        return this;
    }

    /**
     * Registers a version whose wrapped DEK will be read from {@code path} when build runs. The
     * highest version registered across every withKeyFile/withEphemeralKey call becomes the built
     * ring's current version.
     *
     * @throws IllegalArgumentException a key file is already registered for this version
     */
    public KeyRingBuilder withKeyFile(int version, Path path) {
        Objects.requireNonNull(path, "path");
        if (keyFiles.putIfAbsent(version, path) != null)
            throw new IllegalArgumentException("A key file is already registered for version " + version + ".");
        return this;
    }

    /** {@link #withKeyFile(int, Path)} for a path string. */
    public KeyRingBuilder withKeyFile(int version, String path) {
        return withKeyFile(version, Path.of(path));
    }

    /**
     * Registers a version whose DEK is generated fresh at build time (via the factory's
     * createEphemeralAsync) and never written to or read from disk - it lives only as long as the
     * built ring. Unless rotation is turned off, the highest ephemeral version must be above every
     * key file's version, so rotation never replaces a key file as the current version.
     */
    public KeyRingBuilder withEphemeralKey(int version) {
        ephemeralVersions.add(version);
        return this;
    }

    /**
     * Reads each registered key file's wrapped bytes, mints each registered ephemeral key, and
     * returns a populated ring - on a virtual thread, so the caller never blocks on a key-wrapper
     * call. If anything fails partway (an unreadable file, an unwrap failure, a duplicate version),
     * every provider created so far is closed and the future fails with the cause.
     *
     * @throws IllegalStateException no key wrapper, no crypto provider factory, no key refresh
     *                               interval, or no key files/ephemeral keys were configured; or
     *                               ephemeral key rotation is on and a key file's version is above
     *                               every ephemeral version
     */
    public CompletableFuture<KeyRingImpl> buildAsync() {
        if (keyWrapper == null)
            throw new IllegalStateException("A key wrapper is required - call withKeyWrapper first.");
        if (cryptoProviderFactory == null)
            throw new IllegalStateException("A crypto provider factory is required - call withCryptoProviderFactory first.");
        if (keyFiles.isEmpty() && ephemeralVersions.isEmpty())
            throw new IllegalStateException("At least one key file or ephemeral key is required - call withKeyFile or withEphemeralKey first.");
        if (keyRefreshInterval == null)
            throw new IllegalStateException("A key refresh interval is required - call withKeyRefreshInterval first.");
        if (!ephemeralVersions.isEmpty() && ephemeralKeyRotationInterval != null && !keyFiles.isEmpty()) {
            // Rotation adds at the current version + 1: above a key file, it would make an in-memory
            // key current and every later encrypt would be lost on restart.
            int highestKeyFile = keyFiles.lastKey();
            if (highestKeyFile > Collections.max(ephemeralVersions))
                throw new IllegalStateException("Key file version " + highestKeyFile + " is above every ephemeral version, so the first scheduled "
                        + "rotation would replace it as the current version and new values would be encrypted under a key that does not survive "
                        + "a restart. Register the ephemeral key at a version above every key file, or call withoutEphemeralKeyRotation().");
        }

        // A snapshot: changing the builder afterwards doesn't change a build in progress.
        var plan = new Plan(Map.copyOf(new TreeMap<>(keyFiles)), List.copyOf(ephemeralVersions), keyWrapper, cryptoProviderFactory,
                formatProvider, logger != null ? logger : LoggerFactory.getLogger(KeyRingImpl.class), keyRefreshInterval,
                maxRefreshFailures, ephemeralKeyRotationInterval, ephemeralKeyRetention);

        var result = new CompletableFuture<KeyRingImpl>();
        Thread.ofVirtual().name("hkdfguard-key-ring-build").start(() -> {
            try {
                result.complete(plan.build());
            } catch (Throwable t) {
                result.completeExceptionally(t);
            }
        });
        return result;
    }

    private record Plan(Map<Integer, Path> keyFiles, List<Integer> ephemeralVersions, KeyWrapper keyWrapper,
                        CryptoProviderFactory factory, EncryptedFormatProvider formatProvider, Logger logger,
                        int keyRefreshInterval, Integer maxRefreshFailures, Duration rotationInterval, Duration retention) {

        KeyRingImpl build() throws Exception {
            var ring = new KeyRingImpl(formatProvider);
            try {
                for (var keyFile : new TreeMap<>(keyFiles).entrySet()) {
                    // Read through the key wrapper: a native KMS reads its own key files, with its
                    // own checks on who could have written them.
                    var wrapped = await(keyWrapper.readKeyFileAsync(keyFile.getValue()));
                    var provider = await(factory.createAsync(keyWrapper, wrapped, keyRefreshInterval, maxRefreshFailures));
                    addOwned(ring, keyFile.getKey(), provider);
                }

                for (var version : ephemeralVersions) {
                    var provider = await(factory.createEphemeralAsync(keyWrapper, keyRefreshInterval, maxRefreshFailures));
                    addOwned(ring, version, provider);
                }

                if (!ephemeralVersions.isEmpty() && rotationInterval != null) {
                    // Each rotation creates its key exactly as an ephemeral version above was created.
                    ring.configureEphemeralKeyRetention(retention, ephemeralVersions);
                    ring.startEphemeralKeyRotation(rotationInterval, () -> factory
                            .createEphemeralAsync(keyWrapper, keyRefreshInterval, maxRefreshFailures)
                            .thenApply(provider -> (DataEncryptionKey) new DataEncryptionKeyImpl(provider)), logger);
                }

                return ring;
            } catch (Exception e) {
                ring.close();
                throw e;
            }
        }

        private static <T> T await(CompletableFuture<T> future) throws Exception {
            try {
                return future.get();
            } catch (ExecutionException e) {
                throw e.getCause() instanceof Exception cause ? cause : e;
            } catch (CompletionException e) {
                throw e.getCause() instanceof Exception cause ? cause : e;
            }
        }

        private static void addOwned(KeyRingImpl ring, int version, CryptoProvider provider) {
            var key = new DataEncryptionKeyImpl(provider);
            try {
                ring.add(version, key);
            } catch (RuntimeException e) {
                key.close();
                throw e;
            }
        }
    }
}
