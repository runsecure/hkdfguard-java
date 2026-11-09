package io.github.runsecure.hkdfguard.cache.jsonsecretsfile;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl;
import io.github.runsecure.hkdfguard.cache.filepersecret.FilePerSecretCacheImpl;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.CacheMetrics;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import io.github.runsecure.hkdfguard.securefile.FileTooLargeException;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.securefile.TrustedFile;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import java.util.function.ToIntFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ProtectedReadOnlyCache} over one JSON file holding every secret, as a pipeline's
 * {@code SecretPipelineWriter.writeJsonSecrets} writes it: a single object whose members map each
 * secret's name to its value, already encrypted under the key ring and formatted
 * ({@code enc::v{version}::{base64}}). Nothing is read up front: the first lookup reads the whole
 * file, authenticates every value in it, and keeps them - still encrypted, exactly as the file
 * holds them - so every later lookup is served from memory without touching the disk.
 * <p>
 * <b>The file is read through {@link TrustedFile}.</b> It is refused - with an
 * {@link UncheckedIOException} whose cause is an {@link AccessDeniedException}, and nothing kept -
 * unless it and every folder above it are owned, and modifiable, only by the operating system's
 * administrators and the principals the {@link KeyFileTrust} adds, with no untrusted symbolic link
 * on the way. Add the account that deploys secrets, never the one the application runs as.
 * <p>
 * <b>Every value is bound to its name.</b> A member's value must be encrypted with the purpose
 * {@link ProtectedConfigurationPurpose#forKey ProtectedConfigurationPurpose.forKey(name)} - as
 * {@code AesGcmPipelineDataProtectorImpl.encrypt(value, name)} writes it - and a value moved under
 * any other name fails authentication. The file is delivered as one, so it is loaded as one: a
 * value that fails authentication, or names a key version the ring doesn't hold, fails the whole
 * load with a {@link CryptographicException} or {@link NoSuchElementException}, and nothing is
 * kept. A load that fails - for that or any reason below but a missing file - is remembered for
 * {@link #RETRY_AFTER_FAILURE}: lookups in that time fail at once with the same exception, without
 * reading the file or waiting for one another, and the first lookup after it reads the file again.
 * A file that stays invalid therefore costs one read every few seconds, not one per lookup.
 * <p>
 * <b>The file must be exactly that object</b> - UTF-8 JSON, one member per secret, each name a
 * valid FilePerSecretCacheImpl name ({@link FilePerSecretCacheImpl#isValidName}), no name twice
 * ignoring case, each value a non-empty string - or it is refused with an
 * {@link InvalidSecretDataException}; a value that isn't a formatted value is refused by the format
 * provider, with an {@link EncryptedFormatException}. Names are looked up ignoring ASCII case, as
 * the values are bound; any name that couldn't be one is reported missing - decrypt returns 0 - so
 * the cache can sit in a {@link ProtectedCacheCollectionImpl} beside sources with other naming
 * rules. A missing file, or folder above it, reports every secret missing, and isn't remembered: it
 * is looked for again on the next lookup. A file longer than the maximum given is refused with an
 * InvalidSecretDataException, reading no more than one byte past it; any other failure to read it
 * propagates, an {@link IOException} wrapped in an UncheckedIOException.
 * <p>
 * The file is read on the thread that makes the first lookup, as FilePerSecretCacheImpl reads its
 * files: it is small and local. A lookup made while it is being loaded waits for that load. So
 * decryptAsync and findMaxDecryptedLengthAsync are the interface's, which call the synchronous
 * members and return a completed future.
 * <p>
 * The values loaded are kept for the life of the instance: a file changed after it was loaded is
 * picked up by a new cache instance. Each value decrypts with the key version it names, so it
 * keeps decrypting after a key rotation for as long as the ring holds that version.
 * <p>
 * Telemetry: each load of the file is a {@link SpanNames.Cache#POPULATE} span on
 * {@link HkdfGuardTelemetry#CACHE}, counted in {@link CacheMetrics#operations()} as "success",
 * "not_found" or "error"; with sensitive logging on, the file's path and each looked-up name (never
 * a value) are logged.
 */
public final class JsonSecretsFileReadOnlyCacheImpl implements ProtectedReadOnlyCache {
    /** How long a failed load is remembered before the file is read again. */
    public static final Duration RETRY_AFTER_FAILURE = Duration.ofSeconds(5);

    /** The longest file read by default, in bytes: room for hundreds of formatted secrets. */
    public static final int DEFAULT_MAX_FILE_LENGTH = 1024 * 1024;

    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);
    private static final AttributeKey<String> OPERATION_NAME = AttributeKey.stringKey(AttributeNames.OPERATION_NAME);
    private static final AttributeKey<String> RESULT = AttributeKey.stringKey(AttributeNames.RESULT);

    private final Path filePath;
    private final KeyFileTrust trust;
    private final KeyRing keyRing;
    private final EncryptedFormatProvider formatProvider;
    private final int maxFileLength;
    private final Logger logger;

    // One load at a time; once a load succeeds, its values are kept and the lock is never needed again.
    private final ReentrantLock loading = new ReentrantLock();
    private volatile Map<String, KeyTrackingValue> values;

    // The last load's failure and when it happened, until a load succeeds or finds no file.
    private record Failure(RuntimeException error, long at) {
    }

    private volatile Failure lastFailure;

    // Tests: the monotonic clock a failure's age is measured with.
    LongSupplier nanoTime = System::nanoTime;

    /**
     * A cache reading files of up to {@link #DEFAULT_MAX_FILE_LENGTH} bytes, logging through this
     * class's SLF4J logger.
     *
     * @param filePath       the JSON file holding the secrets, absolute or relative to the working
     *                       directory
     * @param trust          who besides administrators is trusted to have written the file and the
     *                       folders above it; {@link KeyFileTrust#ADMINISTRATORS_ONLY} for no one
     * @param keyRing        supplies the key each value names. Owned by the caller.
     * @param formatProvider parses each formatted value
     * @throws NoSuchFileException filePath doesn't name an existing file
     * @see #JsonSecretsFileReadOnlyCacheImpl(Path, KeyFileTrust, KeyRing, EncryptedFormatProvider, int, Logger)
     */
    public JsonSecretsFileReadOnlyCacheImpl(Path filePath, KeyFileTrust trust, KeyRing keyRing, EncryptedFormatProvider formatProvider)
            throws NoSuchFileException {
        this(filePath, trust, keyRing, formatProvider, DEFAULT_MAX_FILE_LENGTH, null);
    }

    /**
     * A cache reading files of up to {@code maxFileLength} bytes, logging through {@code logger}.
     *
     * @param filePath       the JSON file holding the secrets, absolute or relative to the working
     *                       directory
     * @param trust          who besides administrators is trusted to have written the file and the
     *                       folders above it; {@link KeyFileTrust#ADMINISTRATORS_ONLY} for no one
     * @param keyRing        supplies the key each value names. Owned by the caller: the cache never
     *                       closes keys.
     * @param formatProvider parses each formatted value - the same format the values were written in
     * @param maxFileLength  the longest file read, in bytes; the read buffer is this large, so keep
     *                       it close to the largest file expected
     * @param logger         receives a debug entry per load and per looked-up name while sensitive
     *                       logging is enabled, and an error entry per failed load; null for this
     *                       class's SLF4J logger
     * @throws NullPointerException     filePath, trust, keyRing or formatProvider is null
     * @throws IllegalArgumentException filePath is empty, or maxFileLength isn't positive or is too
     *                                  large for one array
     * @throws NoSuchFileException      filePath doesn't name an existing file
     */
    public JsonSecretsFileReadOnlyCacheImpl(Path filePath, KeyFileTrust trust, KeyRing keyRing, EncryptedFormatProvider formatProvider,
            int maxFileLength, Logger logger) throws NoSuchFileException {
        Objects.requireNonNull(filePath, "filePath");
        Objects.requireNonNull(trust, "trust");
        Objects.requireNonNull(keyRing, "keyRing");
        Objects.requireNonNull(formatProvider, "formatProvider");
        if (filePath.toString().isEmpty())
            throw new IllegalArgumentException("filePath must not be empty.");
        // TrustedFile's own limit: the buffer is one byte longer than the longest file accepted.
        if (maxFileLength <= 0 || maxFileLength >= Integer.MAX_VALUE - 8)
            throw new IllegalArgumentException("maxFileLength must be from 1 to " + (Integer.MAX_VALUE - 9) + "; it is " + maxFileLength + ".");

        this.filePath = filePath.toAbsolutePath().normalize();
        if (!Files.isRegularFile(this.filePath))
            throw new NoSuchFileException(this.filePath.toString(), null, "The secrets file '" + this.filePath + "' doesn't exist.");

        this.trust = trust;
        this.keyRing = keyRing;
        this.formatProvider = formatProvider;
        this.maxFileLength = maxFileLength;
        this.logger = logger != null ? logger : LoggerFactory.getLogger(JsonSecretsFileReadOnlyCacheImpl.class);
    }

    /**
     * The absolute, normalized path of the JSON file the secrets are read from.
     *
     * @return the file's path
     */
    public Path getFilePath() {
        return filePath;
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException       name is null
     * @throws CryptographicException     a value in the file wasn't encrypted for its name, or was altered
     * @throws InvalidSecretDataException the file isn't the secrets object, or is too long
     * @throws EncryptedFormatException   a value in the file isn't a formatted value
     * @throws UncheckedIOException       the file's location isn't trusted ({@link AccessDeniedException}),
     *                                    this account may not read it, or it couldn't be read
     * @throws NoSuchElementException     a value's key version isn't in the ring
     */
    @Override
    public int decrypt(String name, byte[] result) {
        return decryptTraced(name, value -> decryptValue(name, value, result));
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException       name is null
     * @throws CryptographicException     a value in the file wasn't encrypted for its name, or was altered
     * @throws InvalidSecretDataException the file isn't the secrets object, or is too long
     * @throws EncryptedFormatException   a value in the file isn't a formatted value
     * @throws UncheckedIOException       the file's location isn't trusted ({@link AccessDeniedException}),
     *                                    this account may not read it, or it couldn't be read
     * @throws NoSuchElementException     a value's key version isn't in the ring
     */
    @Override
    public int decrypt(String name, char[] result) {
        // AEAD ciphertext is always at least as long as the plaintext it encloses, so the value's
        // length is a safe upper bound for the decrypted UTF-8 byte count.
        return decryptTraced(name, value -> Utf8Utility.decodeWritten(value.value().length, bytes -> decryptValue(name, value, bytes), result));
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException       name is null
     * @throws CryptographicException     a value in the file wasn't encrypted for its name, or was altered
     * @throws InvalidSecretDataException the file isn't the secrets object, or is too long
     * @throws EncryptedFormatException   a value in the file isn't a formatted value
     * @throws UncheckedIOException       the file's location isn't trusted ({@link AccessDeniedException}),
     *                                    this account may not read it, or it couldn't be read
     * @throws NoSuchElementException     a value's key version isn't in the ring
     */
    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        var value = getValue(name);
        return value == null ? OptionalInt.empty() : OptionalInt.of(value.value().length);
    }

    private int decryptTraced(String name, ToIntFunction<KeyTrackingValue> decrypt) {
        try (var op = HkdfGuardTelemetry.CACHE.startSpan(SpanNames.Cache.DECRYPT)) {
            if (HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled()) {
                HkdfGuardTelemetry.CACHE.logSensitiveOperation(op.span(), SpanNames.Cache.DECRYPT, Attributes.of(NAME, String.valueOf(name)));
                HkdfGuardLog.sensitiveOperationLogged(logger, SpanNames.Cache.DECRYPT, String.valueOf(name));
            }

            try {
                var value = getValue(name);
                return value == null ? 0 : decrypt.applyAsInt(value);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    private int decryptValue(String name, KeyTrackingValue value, byte[] result) {
        return keyRing.get(value.keyVersion()).decrypt(value.value(), ProtectedConfigurationPurpose.aadFor(name), result);
    }

    // name's value, loading the file on the first lookup; null if name couldn't be a secret's name,
    // the file is missing, or it holds no value for name.
    private KeyTrackingValue getValue(String name) {
        Objects.requireNonNull(name, "name");

        // Checked first: the map ignores case as String.CASE_INSENSITIVE_ORDER does, which folds some
        // non-ASCII letters onto ASCII ones ('ı' onto 'I'), and names are bound ignoring ASCII case only.
        if (!FilePerSecretCacheImpl.isValidName(name))
            return null;

        var loaded = values;
        if (loaded == null)
            loaded = load();
        return loaded == null ? null : loaded.get(name);
    }

    // Throws the last load's failure again while it is recent; the same exception, so callers see
    // the same type and message as the lookup that read the file.
    private void throwIfRecentlyFailed() {
        var failed = lastFailure;
        if (failed != null && nanoTime.getAsLong() - failed.at() < RETRY_AFTER_FAILURE.toNanos())
            throw failed.error();
    }

    // Reads, parses and authenticates the whole file, keeping its values once every one passes;
    // null if the file is missing.
    private Map<String, KeyTrackingValue> load() {
        // A recent failure answers without the lock, so lookups don't queue behind each other.
        throwIfRecentlyFailed();
        loading.lock();
        try {
            // Another lookup may have loaded it, or failed to, while this one waited.
            var loaded = values;
            if (loaded != null)
                return loaded;
            throwIfRecentlyFailed();

            try (var op = HkdfGuardTelemetry.CACHE.startSpan(SpanNames.Cache.POPULATE)) {
                if (HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled()) {
                    HkdfGuardTelemetry.CACHE.logSensitiveOperation(op.span(), SpanNames.Cache.POPULATE, Attributes.of(NAME, filePath.toString()));
                    HkdfGuardLog.sensitiveOperationLogged(logger, SpanNames.Cache.POPULATE, filePath.toString());
                }

                try {
                    var contents = read();
                    if (contents == null) {
                        lastFailure = null;
                        recordOperation("not_found");
                        return null;
                    }

                    var parsed = parse(contents);
                    for (var secret : parsed.entrySet())
                        authenticate(secret.getKey(), secret.getValue());

                    recordOperation("success");
                    lastFailure = null;
                    values = parsed;
                    return parsed;
                } catch (RuntimeException e) {
                    op.recordException(e);
                    HkdfGuardLog.operationFailed(logger, SpanNames.Cache.POPULATE, e);
                    recordOperation("error");
                    lastFailure = new Failure(e, nanoTime.getAsLong());
                    throw e;
                }
            }
        } finally {
            loading.unlock();
        }
    }

    // The file's contents from TrustedFile; null if the file or a folder above it doesn't exist.
    private byte[] read() {
        try {
            return TrustedFile.readAsync(filePath, trust, maxFileLength).join();
        } catch (RuntimeException e) {
            // The file is read on this thread, so the future is already complete: join only
            // unwraps its failure.
            switch (KeyWrapperFutures.unwrap(e)) {
                case NoSuchFileException _ -> {
                    return null;
                }
                case FileTooLargeException tooLarge -> throw new InvalidSecretDataException(tooLarge.getMessage());
                case IOException io -> throw new UncheckedIOException(io.getMessage(), io);
                case RuntimeException runtime -> throw runtime;
                case Error error -> throw error;
                default -> throw e;
            }
        }
    }

    // The secrets object's members, each value parsed but not yet authenticated, by name ignoring
    // ASCII case - every name is ASCII, so ignoring case is ignoring ASCII case. The values are
    // ciphertext, so Strings are safe.
    private Map<String, KeyTrackingValue> parse(byte[] contents) {
        if (!isUtf8(contents))
            throw invalid("isn't valid JSON: it isn't UTF-8 text");

        var parsed = new TreeMap<String, KeyTrackingValue>(String.CASE_INSENSITIVE_ORDER);
        try {
            var reader = new JsonReader(contents, contents.length);
            if (!reader.read())
                throw invalid("isn't valid JSON: it is empty");
            if (reader.token() != Token.START_OBJECT)
                throw invalid("holds a " + reader.token() + ", not an object of secrets");

            // The reader throws on anything malformed or incomplete, so inside the object each token
            // read is a member's name or the object's end, and after a name, its value.
            while (true) {
                reader.read();
                if (reader.token() == Token.END_OBJECT)
                    break;

                var name = reader.getString();
                if (!FilePerSecretCacheImpl.isValidName(name))
                    throw invalid("names a secret '" + name + "', which isn't a secret's name");

                reader.read();
                var encrypted = reader.token() == Token.STRING ? reader.getString().strip() : "";
                if (encrypted.isEmpty())
                    throw invalid("holds no value for '" + name + "': each must be a non-empty string");
                if (parsed.putIfAbsent(name, formatProvider.parse(encrypted)) != null)
                    throw invalid("names '" + name + "' more than once");
            }

            // Anything after the object - a second value, stray text - throws here.
            reader.read();
        } catch (JsonReader.Malformed e) {
            throw invalid("isn't valid JSON: " + e.getMessage());
        }

        return Collections.unmodifiableMap(parsed);
    }

    private static boolean isUtf8(byte[] contents) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(contents));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    private InvalidSecretDataException invalid(String problem) {
        return new InvalidSecretDataException("The secrets file '" + filePath + "' " + problem + ".");
    }

    // Decrypts value once into a buffer that is zeroed at once, so only values that authenticate
    // under their names - and key versions the ring holds - are ever kept.
    private void authenticate(String name, KeyTrackingValue value) {
        var plaintext = new byte[value.value().length];
        try {
            decryptValue(name, value, plaintext);
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    private static void recordOperation(String result) {
        CacheMetrics.operations().add(1, Attributes.of(OPERATION_NAME, SpanNames.Cache.POPULATE, RESULT, result));
    }
}
