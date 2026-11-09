package io.github.runsecure.hkdfguard.cache.filepersecret;

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
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.github.runsecure.hkdfguard.diagnostics.CacheMetrics;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardLog;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.github.runsecure.hkdfguard.securefile.FileTooLargeException;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.securefile.TrustedFile;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.ToIntFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ProtectedReadOnlyCache} over a folder on the local filesystem holding one file per
 * secret: the file named name holds that secret's value, already encrypted under the key ring and
 * formatted ({@code enc::v{version}::{base64}}). Nothing is read up front: the first lookup of a
 * name reads that one file, authenticates its value, and caches it - still encrypted, exactly as
 * the file holds it - so every later lookup is served from memory without touching the disk.
 * Surrounding whitespace in a file, such as a trailing newline, is ignored.
 * <p>
 * <b>Every file is read through {@link TrustedFile}.</b> It is refused - with an
 * {@link UncheckedIOException} whose cause is an {@link AccessDeniedException}, and not cached -
 * unless it and every folder above it are owned, and modifiable, only by the operating system's
 * administrators and the principals the {@link KeyFileTrust} adds, with no untrusted symbolic link
 * on the way. Add the account that deploys secrets, never the one the application runs as.
 * <p>
 * <b>Every value is bound to its name.</b> A file's value must be encrypted with the purpose
 * {@link ProtectedConfigurationPurpose#forKey ProtectedConfigurationPurpose.forKey(name)} - as
 * {@code AesGcmPipelineDataProtectorImpl.encrypt(value, name)}, or
 * {@code ring.createProtector(ProtectedConfigurationPurpose.forKey(name))}, writes it - and a file
 * copied under any other name fails authentication with a {@link CryptographicException} when it
 * is loaded, rather than decrypting as that name's value. A file that fails is not cached, so it is
 * read again on the next lookup.
 * <p>
 * A name is a file name: 1-{@link #MAX_NAME_LENGTH} ASCII letters, digits, '-', '_' and '.', neither
 * starting nor ending with '.', and not one of Windows' reserved device names (see
 * {@link #isValidName}), so it can never reach outside the folder, or name a device. Any other
 * name, a missing file, a missing folder and an empty file are all reported missing - decrypt
 * returns 0 - so the cache can sit in a {@link ProtectedCacheCollectionImpl} beside sources with
 * other naming rules. A missing secret isn't remembered: its file is looked for again on the next
 * lookup. Names are matched exactly, unlike the interface's other caches, and files are found as
 * the filesystem finds them: exactly on Linux, ignoring case on Windows and, by default, macOS. A
 * file longer than {@link #MAX_FILE_LENGTH} bytes is refused with an
 * {@link InvalidSecretDataException}, reading no more than one byte past that; any other failure to
 * read it propagates, an {@link IOException} wrapped in an {@link UncheckedIOException}, and
 * nothing is cached.
 * <p>
 * A file is read on the thread that looks it up, as {@code TrustedKeyFile} reads a key file: it is
 * small and local. So decryptAsync and findMaxDecryptedLengthAsync are the interface's, which call
 * the synchronous members and return a completed future.
 * <p>
 * A cached value is kept for the life of the instance: a file changed after its secret was loaded
 * is picked up by a new cache instance. Each value decrypts with the key version it names, so it
 * keeps decrypting after a key rotation for as long as the ring holds that version.
 * <p>
 * Telemetry: each file load is a {@link SpanNames.Cache#POPULATE} span on
 * {@link HkdfGuardTelemetry#CACHE}, counted in {@link CacheMetrics#operations()} as "success",
 * "not_found" or "error"; with sensitive logging on, the secret's name (never a value) is logged.
 */
public final class FilePerSecretCacheImpl implements ProtectedReadOnlyCache {
    /** The longest name a secret's file can have. */
    public static final int MAX_NAME_LENGTH = 255;

    /** The longest file, in bytes, that is read: room for a formatted secret of about 48 KB. */
    public static final int MAX_FILE_LENGTH = 64 * 1024;

    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);
    private static final AttributeKey<String> OPERATION_NAME = AttributeKey.stringKey(AttributeNames.OPERATION_NAME);
    private static final AttributeKey<String> RESULT = AttributeKey.stringKey(AttributeNames.RESULT);

    private final Path folderPath;
    private final KeyFileTrust trust;
    private final KeyRing keyRing;
    private final EncryptedFormatProvider formatProvider;
    private final Logger logger;

    // Each loaded secret's value as its file held it: encrypted, bound to its name. Exact names,
    // since each spelling is bound - and authenticated - separately.
    private final ConcurrentHashMap<String, KeyTrackingValue> values = new ConcurrentHashMap<>();

    /**
     * A cache logging through this class's SLF4J logger.
     *
     * @see #FilePerSecretCacheImpl(Path, KeyFileTrust, KeyRing, EncryptedFormatProvider, Logger)
     */
    public FilePerSecretCacheImpl(Path folderPath, KeyFileTrust trust, KeyRing keyRing, EncryptedFormatProvider formatProvider)
            throws NoSuchFileException {
        this(folderPath, trust, keyRing, formatProvider, null);
    }

    /**
     * @param folderPath     the folder holding one file per secret, absolute or relative to the
     *                       working directory
     * @param trust          who besides administrators is trusted to have written the folder and
     *                       its files; {@link KeyFileTrust#ADMINISTRATORS_ONLY} for no one
     * @param keyRing        supplies the key each file's value names. Owned by the caller: the
     *                       cache never closes keys.
     * @param formatProvider parses each file's formatted value - the same format the values were
     *                       written in
     * @param logger         receives a debug entry per loaded name while sensitive logging is
     *                       enabled, and an error entry per failed load; null for this class's
     *                       SLF4J logger
     * @throws NullPointerException     folderPath, trust, keyRing or formatProvider is null
     * @throws IllegalArgumentException folderPath is empty
     * @throws NoSuchFileException      folderPath doesn't name an existing folder
     */
    public FilePerSecretCacheImpl(Path folderPath, KeyFileTrust trust, KeyRing keyRing, EncryptedFormatProvider formatProvider, Logger logger)
            throws NoSuchFileException {
        Objects.requireNonNull(folderPath, "folderPath");
        Objects.requireNonNull(trust, "trust");
        Objects.requireNonNull(keyRing, "keyRing");
        Objects.requireNonNull(formatProvider, "formatProvider");
        if (folderPath.toString().isEmpty())
            throw new IllegalArgumentException("folderPath must not be empty.");

        this.folderPath = folderPath.toAbsolutePath().normalize();
        if (!Files.isDirectory(this.folderPath))
            throw new NoSuchFileException(this.folderPath.toString(), null, "The secrets folder '" + this.folderPath + "' doesn't exist.");

        this.trust = trust;
        this.keyRing = keyRing;
        this.formatProvider = formatProvider;
        this.logger = logger != null ? logger : LoggerFactory.getLogger(FilePerSecretCacheImpl.class);
    }

    /** The absolute, normalized path of the folder the secrets' files are read from. */
    public Path getFolderPath() {
        return folderPath;
    }

    /**
     * Whether name can be a secret's file name, on every platform: 1-{@link #MAX_NAME_LENGTH} ASCII
     * letters, digits, '-', '_' and '.', neither starting nor ending with '.', and not one of Windows'
     * reserved device names (CON, PRN, AUX, NUL, COM0-COM9, LPT0-LPT9), with or without an
     * extension, in any case. Windows drops a trailing '.', so "a." would be the file "a", and opens
     * the device for a reserved name, so a value written there is lost and a read gets the device.
     * The same rule as the .NET FilePerSecretCache.IsValidName.
     */
    public static boolean isValidName(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_NAME_LENGTH || name.charAt(0) == '.' || name.charAt(name.length() - 1) == '.')
            return false;

        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'))
                return false;
        }
        return !isReservedDeviceName(name);
    }

    // CON, PRN, AUX, NUL, COM0-9 and LPT0-9, as the whole name or before its first '.', ignoring case.
    private static boolean isReservedDeviceName(String name) {
        var dot = name.indexOf('.');
        var stem = dot < 0 ? name : name.substring(0, dot);
        if (stem.length() == 3)
            return stem.equalsIgnoreCase("CON") || stem.equalsIgnoreCase("PRN") || stem.equalsIgnoreCase("AUX") || stem.equalsIgnoreCase("NUL");
        return stem.length() == 4 && stem.charAt(3) >= '0' && stem.charAt(3) <= '9'
                && (stem.regionMatches(true, 0, "COM", 0, 3) || stem.regionMatches(true, 0, "LPT", 0, 3));
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException        name is null
     * @throws CryptographicException      the file's value wasn't encrypted for this name, or was altered
     * @throws UncheckedIOException        the file's location isn't trusted ({@link AccessDeniedException}),
     *                                     this account may not read it, or it couldn't be read
     * @throws InvalidSecretDataException  the file is longer than {@link #MAX_FILE_LENGTH} bytes
     * @throws EncryptedFormatException    the file doesn't hold a formatted value
     * @throws NoSuchElementException      the value's key version is no longer in the ring
     */
    @Override
    public int decrypt(String name, byte[] result) {
        return decryptTraced(name, value -> decryptValue(name, value, result));
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException        name is null
     * @throws CryptographicException      the file's value wasn't encrypted for this name, or was altered
     * @throws UncheckedIOException        the file's location isn't trusted ({@link AccessDeniedException}),
     *                                     this account may not read it, or it couldn't be read
     * @throws InvalidSecretDataException  the file is longer than {@link #MAX_FILE_LENGTH} bytes
     * @throws EncryptedFormatException    the file doesn't hold a formatted value
     * @throws NoSuchElementException      the value's key version is no longer in the ring
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
     * @throws NullPointerException        name is null
     * @throws CryptographicException      the file's value wasn't encrypted for this name, or was altered
     * @throws UncheckedIOException        the file's location isn't trusted ({@link AccessDeniedException}),
     *                                     this account may not read it, or it couldn't be read
     * @throws InvalidSecretDataException  the file is longer than {@link #MAX_FILE_LENGTH} bytes
     * @throws EncryptedFormatException    the file doesn't hold a formatted value
     * @throws NoSuchElementException      the value's key version is no longer in the ring
     */
    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        var value = getValue(name);
        return value == null ? OptionalInt.empty() : OptionalInt.of(value.value().length);
    }

    private int decryptTraced(String name, ToIntFunction<KeyTrackingValue> decrypt) {
        try (var op = HkdfGuardTelemetry.CACHE.startSpan(SpanNames.Cache.DECRYPT)) {
            if (HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled())
                HkdfGuardTelemetry.CACHE.logSensitiveOperation(op.span(), SpanNames.Cache.DECRYPT, Attributes.of(NAME, String.valueOf(name)));

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

    // The cached value for name, loading it from its file on a miss; null if name can't be a file
    // name or there is no value. Concurrent misses may each load the file; the first stored is kept.
    private KeyTrackingValue getValue(String name) {
        Objects.requireNonNull(name, "name");
        var cached = values.get(name);
        if (cached != null)
            return cached;
        if (!isValidName(name))
            return null;

        try (var op = HkdfGuardTelemetry.CACHE.startSpan(SpanNames.Cache.POPULATE)) {
            if (HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled()) {
                HkdfGuardTelemetry.CACHE.logSensitiveOperation(op.span(), SpanNames.Cache.POPULATE, Attributes.of(NAME, name));
                HkdfGuardLog.sensitiveOperationLogged(logger, SpanNames.Cache.POPULATE, name);
            }

            try {
                var encrypted = read(name);
                if (encrypted == null) {
                    recordOperation("not_found");
                    return null;
                }

                var value = formatProvider.parse(encrypted);
                authenticate(name, value);
                recordOperation("success");
                var stored = values.putIfAbsent(name, value);
                return stored != null ? stored : value;
            } catch (RuntimeException e) {
                op.recordException(e);
                HkdfGuardLog.operationFailed(logger, SpanNames.Cache.POPULATE, e);
                recordOperation("error");
                throw e;
            }
        }
    }

    // Decrypts value once into a buffer that is zeroed at once, so only a value that authenticates
    // under name - and a key version the ring holds - is ever cached.
    private void authenticate(String name, KeyTrackingValue value) {
        var plaintext = new byte[value.value().length];
        try {
            decryptValue(name, value, plaintext);
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    // The secret's formatted value from its trusted file, trimmed; null if the file or folder
    // doesn't exist, or the file is empty. The value is ciphertext, so a String is safe.
    private String read(String name) {
        byte[] contents;
        try {
            contents = TrustedFile.readAsync(folderPath.resolve(name), trust, MAX_FILE_LENGTH).join();
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

        var encrypted = new String(contents, StandardCharsets.UTF_8).strip();
        return encrypted.isEmpty() ? null : encrypted;
    }

    private static void recordOperation(String result) {
        CacheMetrics.operations().add(1, Attributes.of(OPERATION_NAME, SpanNames.Cache.POPULATE, RESULT, result));
    }
}
