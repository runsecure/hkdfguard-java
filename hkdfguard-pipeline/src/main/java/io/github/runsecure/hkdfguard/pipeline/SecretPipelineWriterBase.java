package io.github.runsecure.hkdfguard.pipeline;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapperFutures;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cache.filepersecret.FilePerSecretCacheImpl;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

/**
 * The shared plumbing of a {@link SecretPipelineWriter} over one secret store: the store's writer
 * supplies only {@link #readSecret} (and {@link #readSecretAsync}, for an asynchronous client), which
 * reads one secret and hands its values to {@link #protectSecret}, {@link #protect} or
 * {@link #protectKeys}. Everything else - naming, grouping, encrypting, keeping and writing - is
 * here. No key ring is involved: the protector's key is the only one.
 * <p>
 * A secret name is the store's name for a secret, optionally followed by {@link #KEY_SEPARATOR} and
 * a key it holds: "prod/app#password" is the password key of the secret prod/app. A name without one
 * reads the store's default key, if it has one, or else the secret's whole value. The secrets named
 * are grouped by the store's name, so each is read once however many of its keys are listed.
 * <p>
 * A secret's file name is its name with every '/' and '#' replaced by {@link #FILE_NAME_SEPARATOR}
 * (see {@link #getFileName}): "prod/app#password" is written as prod__app__password. A name whose
 * file name FilePerSecretCacheImpl couldn't read is refused. Each value is encrypted bound to its file
 * name - {@code encrypt(value, fileName)} - which is the name FilePerSecretCacheImpl decrypts it
 * under, so a renamed file fails authentication.
 * <p>
 * A secret's plaintext never becomes a String: {@link #protect} takes it as UTF-8 bytes, which the
 * store's writer keeps in an array of its own, and decodes it into a char array for the protector,
 * zeroing it. Unlike .NET, the JVM can't pin an array: a compacting collector may leave a moved copy
 * behind, which zeroing can't reach. The protector is the caller's and is never closed, so its key
 * can be handed to the wrap process once the files are written. An instance isn't thread-safe: make
 * one pull at a time, and read {@link #getProtectedSecrets()} once it has completed.
 * <p>
 * The secrets can be written as one file each ({@link #writeProtectedSecretFiles}, the folder
 * FilePerSecretCacheImpl reads) or as one JSON file of them all ({@link #writeJsonSecrets}, the
 * file JsonSecretsFileReadOnlyCacheImpl reads) - and each to a stream instead, a tar archive of the
 * files ({@link #writeProtectedSecretFilesAsync}) or the JSON ({@link #writeJsonSecretsAsync}), for
 * a remote command's standard input such as {@code ssh -T host sudo -n tar -x ...}. The streamed
 * forms take what {@link #getProtectedSecrets()} holds when they are called, and write it on a
 * virtual thread of their own.
 */
public abstract class SecretPipelineWriterBase implements SecretPipelineWriter {
    /** Separates a secret's name from the key it reads: "prod/app#password". */
    public static final char KEY_SEPARATOR = '#';

    /** Replaces each '/' and '#' of a secret name in its file name. */
    public static final String FILE_NAME_SEPARATOR = "__";

    // rw-r--r--: what each file in a tar archive is unpacked as.
    private static final int SECRET_FILE_MODE = 0644;

    // Names the file each write goes to before it is renamed into place: unguessable, so no one can
    // make a write fail by creating that name first.
    private static final SecureRandom TEMPORARY_NAMES = new SecureRandom();

    private final PipelineDataProtector protector;

    // The secrets to pull, by the store's name, in the order named: each is read once, for its whole
    // value and its keys.
    private final Map<String, List<SecretRequest>> requests = new LinkedHashMap<>();

    // Each secret's encrypted, formatted value, by file name. File names are found ignoring case on
    // Windows and macOS, so two differing only in case are refused as one.
    private final Map<String, String> writableProtectedSecrets = newValues();
    private final Map<String, String> protectedSecrets = Collections.unmodifiableMap(writableProtectedSecrets);
    private boolean pulled;

    /**
     * A writer whose names without a key read the secret's whole value.
     *
     * @see #SecretPipelineWriterBase(PipelineDataProtector, List, Predicate, String)
     */
    protected SecretPipelineWriterBase(PipelineDataProtector protector, List<String> secretNames, Predicate<String> isValidSecretName) {
        this(protector, secretNames, isValidSecretName, null);
    }

    /**
     * @param protector         encrypts every value read. Owned by the caller: the writer never
     *                          closes it.
     * @param secretNames       the secrets to pull, each a name with the key to read after '#' if
     *                          any. Copied: a later change to the list isn't seen.
     * @param isValidSecretName whether the store can hold a secret by a name, before any '#'
     * @param defaultKey        the key a name without one reads, for a store whose secrets are all
     *                          sets of keys (HashiCorp Vault's KV); null when such a name reads the
     *                          secret's whole value
     * @throws NullPointerException     protector, secretNames or isValidSecretName is null
     * @throws IllegalArgumentException secretNames is empty, or holds a null, a name the store can't
     *                                  hold (with a key), one whose file name isn't one
     *                                  FilePerSecretCacheImpl can read, or two with the same file
     *                                  name, in any case; or defaultKey is empty or holds '#'
     */
    protected SecretPipelineWriterBase(PipelineDataProtector protector, List<String> secretNames, Predicate<String> isValidSecretName,
            String defaultKey) {
        this.protector = Objects.requireNonNull(protector, "protector");
        Objects.requireNonNull(secretNames, "secretNames");
        Objects.requireNonNull(isValidSecretName, "isValidSecretName");
        if (defaultKey != null && (defaultKey.isEmpty() || defaultKey.indexOf(KEY_SEPARATOR) >= 0))
            throw new IllegalArgumentException("The default key '" + defaultKey + "' isn't a key.");

        addRequests(secretNames, isValidSecretName, defaultKey);
    }

    /** {@inheritDoc} */
    @Override
    public final Map<String, String> getProtectedSecrets() {
        return protectedSecrets;
    }

    /**
     * The file a secret name is written as: the name with every '/' and '#' replaced by
     * {@link #FILE_NAME_SEPARATOR} - "prod/app#password" is prod__app__password - and the name its
     * value is bound to, so the one to look it up by in FilePerSecretCacheImpl.
     *
     * @throws NullPointerException secretName is null
     */
    public static String getFileName(String secretName) {
        Objects.requireNonNull(secretName, "secretName");
        return secretName.replace("/", FILE_NAME_SEPARATOR).replace(String.valueOf(KEY_SEPARATOR), FILE_NAME_SEPARATOR);
    }

    /**
     * Reads every secret named in the constructor from the store, one after another, and encrypts
     * each value, keeping it in {@link #getProtectedSecrets()} - replacing whatever an earlier pull
     * kept. All of them are read before any missing one is reported. Cancelling the returned future
     * cancels the read in progress, and keeps nothing.
     *
     * @return completes once every secret has been read; fails with {@link NoSuchElementException}
     *         when a secret doesn't exist, or has no such key, or its value there is empty or isn't a
     *         value, every other secret being kept. Any other failure {@link #readSecretAsync} fails
     *         with fails it as it is, and nothing is kept.
     */
    @Override
    public final CompletableFuture<Void> pullSecretsAsync() {
        writableProtectedSecrets.clear();
        pulled = false;

        var pull = new Pull();
        pull.result.whenComplete((ignored, error) -> {
            if (pull.result.isCancelled()) {
                var current = pull.current.get();
                if (current != null)
                    current.cancel(true);
            }
        });
        pull.next();
        return pull.result;
    }

    /**
     * Writes every secret in {@link #getProtectedSecrets()} as a file in {@code folderPath},
     * creating the folder if it doesn't exist: the file named for it, holding its encrypted,
     * formatted value as UTF-8, without a byte order mark. A file already there by that name is
     * replaced; any other file is left as it is.
     * <p>
     * Each file is written to a new file beside it and renamed over it, so a reader never sees it
     * half written, and whatever was there by that name - a symbolic link, a hard link - is
     * replaced, never written through: a link planted in the folder can't make the writer overwrite
     * a file elsewhere. A replaced file's POSIX permissions are kept; on Windows the new file takes
     * the folder's inheritable permissions, as a newly created one always has.
     * <p>
     * Only encrypted values are written, but FilePerSecretCacheImpl refuses a folder or file anyone
     * but administrators and the principals it trusts can modify: write them where the deployment
     * can set that, or set it once they're written. The folder itself is trusted as given, so it
     * must not be one an untrusted account can replace.
     *
     * @param folderPath the folder to write to, absolute or relative to the working directory
     * @throws NullPointerException     folderPath is null
     * @throws IllegalArgumentException folderPath is empty
     * @throws IllegalStateException    no pull has completed
     * @throws IOException              the folder or a file couldn't be written
     */
    @Override
    public final void writeProtectedSecretFiles(Path folderPath) throws IOException {
        Objects.requireNonNull(folderPath, "folderPath");
        if (folderPath.toString().isEmpty())
            throw new IllegalArgumentException("folderPath must not be empty.");
        requirePulled();

        var folder = folderPath.toAbsolutePath().normalize();
        Files.createDirectories(folder);
        for (var secret : writableProtectedSecrets.entrySet())
            replaceFile(folder.resolve(secret.getKey()), secret.getValue().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Replaces the file at {@code path} with {@code content}: writes a new file beside it - created,
     * never opened, so nothing already there is written through - flushes it to disk, carries over
     * the POSIX permissions of a regular file it replaces, and renames it over {@code path}. The
     * rename replaces a link by that name rather than following it. On failure the new file is
     * deleted and whatever was at {@code path} is left as it was.
     */
    private static void replaceFile(Path path, byte[] content) throws IOException {
        var suffix = new byte[8];
        TEMPORARY_NAMES.nextBytes(suffix);
        // A leading '.' is never a secret's file name, so FilePerSecretCacheImpl never reads it.
        var temporary = path.resolveSibling("." + path.getFileName() + "." + HexFormat.of().formatHex(suffix) + ".tmp");
        try {
            try (var channel = FileChannel.open(temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                var buffer = ByteBuffer.wrap(content);
                while (buffer.hasRemaining())
                    channel.write(buffer);
                channel.force(true);
            }

            if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    && Files.getFileStore(temporary).supportsFileAttributeView(PosixFileAttributeView.class))
                Files.setPosixFilePermissions(temporary, Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS));

            Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException | RuntimeException e) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException suppressed) {
                e.addSuppressed(suppressed);
            }
            throw e;
        }
    }

    /**
     * Writes every secret in {@link #getProtectedSecrets()} to one JSON file at {@code filePath},
     * creating its folder if it doesn't exist: a single object with a member per secret, its file
     * name mapped to its encrypted, formatted value, in file-name order (ordinal, so upper case
     * before lower), indented, as UTF-8 without a byte order mark - byte for byte the file .NET's
     * SecretPipelineWriter writes on the same platform, whose line separator ends its lines. A file
     * already there is replaced. Each value is bound to its member's name -
     * {@code decrypt(value, name)} - as it is to its file name in {@link #writeProtectedSecretFiles}.
     * The file is written and renamed into place as each of those files is.
     *
     * @param filePath the file to write, absolute or relative to the working directory
     * @throws NullPointerException     filePath is null
     * @throws IllegalArgumentException filePath is empty
     * @throws IllegalStateException    no pull has completed
     * @throws IOException              the folder or the file couldn't be written
     */
    @Override
    public final void writeJsonSecrets(Path filePath) throws IOException {
        Objects.requireNonNull(filePath, "filePath");
        if (filePath.toString().isEmpty())
            throw new IllegalArgumentException("filePath must not be empty.");
        requirePulled();

        // An absolute path always has a parent: at the least, its root.
        var path = filePath.toAbsolutePath().normalize();
        Files.createDirectories(path.getParent());
        replaceFile(path, JsonSecretsText.of(inFileNameOrder()));
    }

    /**
     * Writes every secret in {@link #getProtectedSecrets()} to {@code destination} as a tar archive
     * of the files {@link #writeProtectedSecretFiles} would write - for a remote tar to unpack, e.g.
     * the stdin of {@code ssh -T host sudo -n tar -x --no-same-owner -f - -C folder}. The archive is
     * PAX, which GNU tar and bsdtar (macOS, and Windows' tar.exe) both read: one regular file per
     * secret, in file-name order (ordinal), mode 0644 and modified now - the values are encrypted,
     * and only who may write them matters to FilePerSecretCacheImpl; with --no-same-owner they
     * belong to whoever unpacks them. destination is flushed and left open: close it afterwards.
     * <p>
     * The archive is built from what getProtectedSecrets() holds when this is called, and written
     * on a virtual thread of its own; cancelling the returned future interrupts it - a stream that
     * ignores interrupts, as a process's standard input does, still finishes the write it is
     * blocked in.
     *
     * @param destination where to write the archive: a process's standard input
     * @return completes once the archive has been written and flushed; fails with the
     *         {@link IOException} the stream fails with
     * @throws NullPointerException  destination is null
     * @throws IllegalStateException no pull has completed
     */
    @Override
    public final CompletableFuture<Void> writeProtectedSecretFilesAsync(OutputStream destination) {
        Objects.requireNonNull(destination, "destination");
        requirePulled();

        var files = new LinkedHashMap<String, byte[]>();
        for (var secret : inFileNameOrder().entrySet())
            files.put(secret.getKey(), secret.getValue().getBytes(StandardCharsets.UTF_8));
        return write(destination, PaxTarArchive.of(files, SECRET_FILE_MODE, Instant.now()), "hkdfguard-pipeline-write-tar");
    }

    /**
     * Writes every secret in {@link #getProtectedSecrets()} to {@code destination} as the JSON
     * object {@link #writeJsonSecrets} would write, byte for byte - for a remote command to store,
     * e.g. the stdin of {@code ssh -T host sudo -n tee /etc/app/secrets.json}. destination is
     * flushed and left open: close it afterwards.
     * <p>
     * The JSON is built from what getProtectedSecrets() holds when this is called, and written on a
     * virtual thread of its own; cancelling the returned future interrupts it - a stream that
     * ignores interrupts, as a process's standard input does, still finishes the write it is
     * blocked in.
     *
     * @param destination where to write the JSON: a process's standard input
     * @return completes once the JSON has been written and flushed; fails with the
     *         {@link IOException} the stream fails with
     * @throws NullPointerException  destination is null
     * @throws IllegalStateException no pull has completed
     */
    @Override
    public final CompletableFuture<Void> writeJsonSecretsAsync(OutputStream destination) {
        Objects.requireNonNull(destination, "destination");
        requirePulled();

        return write(destination, JsonSecretsText.of(inFileNameOrder()), "hkdfguard-pipeline-write-json");
    }

    /** Releases the writer's connection to the store. Does nothing here; a store's writer overrides it. */
    @Override
    public void close() {
    }

    /**
     * Reads the one secret named name and encrypts the value each of {@code requests} asks for into
     * {@code values}, by its file name - with {@link #protectSecret}, {@link #protect} or
     * {@link #protectKeys} - or returns without doing so if it doesn't exist. Any other failure
     * should throw. A request left out of values is reported missing.
     *
     * @param name     the store's name for the secret, before any '#'
     * @param requests what to read from it: its whole value, a key, or both
     * @param values   receives each value encrypted, by file name
     */
    protected abstract void readSecret(String name, List<SecretRequest> requests, Map<String, String> values);

    /**
     * {@link #readSecret} without blocking the caller. The default implementation calls readSecret
     * on a new virtual thread, which cancelling the returned future interrupts; a store with an
     * asynchronous client overrides it. Nothing handed to values after the returned future has
     * completed is kept.
     *
     * @return completes once the secret has been read, or fails as readSecret would throw
     */
    protected CompletableFuture<Void> readSecretAsync(String name, List<SecretRequest> requests, Map<String, String> values) {
        return onVirtualThread("hkdfguard-pipeline-read", () -> readSecret(name, requests, values));
    }

    /**
     * Encrypts a secret's whole value, {@code secret[0, length)}, into values for each of
     * {@code requests} without a key, and, when it is a JSON object, the value of each requested key
     * it holds (see {@link #protectKeys}), by file name. An empty secret holds nothing. secret is the
     * caller's to zero.
     *
     * @throws InvalidSecretDataException the secret isn't UTF-8 text, or is a JSON object holding a
     *                                    key more than once
     */
    protected final void protectSecret(byte[] secret, int length, List<SecretRequest> requests, Map<String, String> values) {
        Objects.checkFromIndexSize(0, length, secret.length);
        if (length == 0)
            return;

        var anyKey = false;
        for (var request : requests) {
            if (request.key() == null)
                values.put(request.fileName(), protect(secret, 0, length, request.fileName()));
            else
                anyKey = true;
        }

        if (anyKey)
            protectKeys(secret, length, requests, values);
    }

    /**
     * Decodes {@code plaintext[offset, offset + length)}'s UTF-8 into a char array and encrypts it
     * bound to fileName; the chars are zeroed. plaintext is the caller's to zero.
     *
     * @return the encrypted, formatted value
     * @throws InvalidSecretDataException plaintext isn't UTF-8 text, which the protector can't
     *                                    encrypt as it is
     */
    protected final String protect(byte[] plaintext, int offset, int length, String fileName) {
        Objects.checkFromIndexSize(offset, length, plaintext.length);

        // Decoding would replace every invalid sequence, so a binary value would be written altered.
        if (!isUtf8(plaintext, offset, length))
            throw new InvalidSecretDataException("The secret isn't UTF-8 text: the pipeline protector encrypts text.");

        // A UTF-8 sequence is never shorter than the UTF-16 it decodes to.
        var chars = new char[length];
        try {
            var out = CharBuffer.wrap(chars);
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            if (decoder.decode(ByteBuffer.wrap(plaintext, offset, length), out, true).isError() || decoder.flush(out).isError())
                throw new InvalidSecretDataException("The secret isn't UTF-8 text: the pipeline protector encrypts text.");

            return protector.encrypt(CharBuffer.wrap(chars, 0, out.position()), fileName);
        } finally {
            ArrayUtility.zeroMemory(chars);
        }
    }

    /**
     * When {@code json[0, length)} is exactly one JSON object, encrypts the value of each key of
     * {@code requests} it holds into values, by file name: a string as its text, a number, true or
     * false as its JSON text. A null, object, array or empty value is left out, and anything else -
     * plain text that merely starts like JSON included - holds no keys. Every value is unescaped into
     * an array of its own, and zeroed once encrypted. json is the caller's to zero.
     *
     * @throws InvalidSecretDataException the object holds a key more than once
     */
    protected final void protectKeys(byte[] json, int length, List<SecretRequest> requests, Map<String, String> values) {
        Objects.checkFromIndexSize(0, length, json.length);
        if (!isUtf8(json, 0, length) || !isObject(json, length))
            return;

        var reader = new JsonReader(json, length);
        reader.read();
        var seen = new HashSet<String>();
        while (nextProperty(reader)) {
            // Not named: a key is part of a secret name, which is never logged.
            if (!seen.add(reader.getString()))
                throw new InvalidSecretDataException("The secret holds a key more than once.");

            var request = find(reader, requests);
            reader.read();
            var token = reader.token();
            if (request != null && (token == Token.STRING || token == Token.NUMBER || token == Token.TRUE || token == Token.FALSE)) {
                var value = protectValue(reader, request.fileName());
                if (value != null)
                    values.put(request.fileName(), value);
            } else {
                reader.skip();
            }
        }
    }

    /**
     * A map of encrypted values by file name, matching file names ignoring ASCII case - what
     * {@link #readSecret} fills. File names are ASCII only, so ignoring case is ignoring ASCII case.
     */
    protected static Map<String, String> newValues() {
        return new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    }

    private void requirePulled() {
        if (!pulled)
            throw new IllegalStateException("No secrets have been pulled: call pullSecretsAsync first.");
    }

    // The secrets by file name in ordinal order, as .NET orders them - not the case-insensitive
    // order writableProtectedSecrets keeps them in. TreeMap(Map), not TreeMap(SortedMap): natural order.
    private Map<String, String> inFileNameOrder() {
        return new TreeMap<>(writableProtectedSecrets);
    }

    // Writes bytes - ciphertext only, so nothing to zero - to destination, and flushes it.
    private static CompletableFuture<Void> write(OutputStream destination, byte[] bytes, String threadName) {
        return onVirtualThread(threadName, () -> {
            destination.write(bytes);
            destination.flush();
        });
    }

    /** Work for a virtual thread, which may fail with an IOException. */
    private interface IoAction {
        void run() throws IOException;
    }

    // Runs action on a new virtual thread, which cancelling the returned future interrupts; what
    // action throws fails the future as it is.
    private static CompletableFuture<Void> onVirtualThread(String threadName, IoAction action) {
        var result = new CompletableFuture<Void>();
        var thread = Thread.ofVirtual().name(threadName).unstarted(() -> {
            try {
                // Cancelled before the thread started, when interrupting it did nothing.
                if (result.isDone())
                    return;
                action.run();
                result.complete(null);
            } catch (Throwable e) {
                result.completeExceptionally(e);
            }
        });
        result.whenComplete((ignored, error) -> {
            if (error instanceof CancellationException)
                thread.interrupt();
        });
        thread.start();
        return result;
    }

    // Unescapes the string the reader is at into an array of its own (a number, true or false is
    // copied as its JSON text) and encrypts it bound to fileName, zeroing it; null if it is empty.
    private String protectValue(JsonReader reader, String fileName) {
        // Unescaped, a string is never longer than it is escaped.
        var bytes = new byte[reader.valueLength()];
        try {
            var length = reader.token() == Token.STRING ? reader.copyString(bytes) : reader.copyRaw(bytes);
            return length == 0 ? null : protect(bytes, 0, length, fileName);
        } finally {
            ArrayUtility.zeroMemory(bytes);
        }
    }

    private void addRequests(List<String> secretNames, Predicate<String> isValidSecretName, String defaultKey) {
        if (secretNames.isEmpty())
            throw new IllegalArgumentException("No secrets are named.");

        var fileNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (var secretName : secretNames) {
            if (secretName == null)
                throw new IllegalArgumentException("A secret name is null.");

            var separator = secretName.indexOf(KEY_SEPARATOR);
            var name = separator < 0 ? secretName : secretName.substring(0, separator);
            var key = separator < 0 ? defaultKey : secretName.substring(separator + 1);
            var fileName = getFileName(secretName);
            if (name.isEmpty() || !isValidSecretName.test(name) || (key != null && key.isEmpty()))
                throw new IllegalArgumentException("'" + secretName + "' isn't a secret name this store can hold, with a key after '"
                        + KEY_SEPARATOR + "' if any.");
            if (!FilePerSecretCacheImpl.isValidName(fileName))
                throw new IllegalArgumentException("'" + secretName + "' can't be written as a file: its file name '" + fileName + "' must be 1-"
                        + FilePerSecretCacheImpl.MAX_NAME_LENGTH + " ASCII letters, digits, '-', '_' and '.', neither starting nor ending with '.', and not"
                        + " a Windows device name (CON, PRN, AUX, NUL, COM0-COM9, LPT0-LPT9), with or without an extension.");
            if (!fileNames.add(fileName))
                throw new IllegalArgumentException("'" + secretName + "' would be written as '" + fileName + "', as another secret named is.");

            requests.computeIfAbsent(name, ignored -> new ArrayList<>()).add(new SecretRequest(secretName, key, fileName));
        }
    }

    // One JSON object and nothing after it but whitespace.
    private static boolean isObject(byte[] json, int length) {
        var reader = new JsonReader(json, length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                return false;

            reader.skip();
            return !reader.read();
        } catch (JsonReader.Malformed e) {
            return false;
        }
    }

    // Moves the reader to the next token and says whether it is a property name - false at the end
    // of the object the reader is in. Inside an object the reader can't run out of input without
    // throwing Malformed, so there is nothing else to check.
    private static boolean nextProperty(JsonReader reader) {
        reader.read();
        return reader.token() == Token.PROPERTY_NAME;
    }

    // The request for the key the reader is at the name of, if any.
    private static SecretRequest find(JsonReader reader, List<SecretRequest> requests) {
        for (var request : requests) {
            if (request.key() != null && reader.valueTextEquals(request.key()))
                return request;
        }
        return null;
    }

    /**
     * Whether bytes[offset, offset + length) is well-formed UTF-8, as .NET's Utf8.IsValid decides:
     * no overlong forms, surrogates, code points past U+10FFFF or truncated sequences. Checked
     * without decoding, so nothing is copied.
     */
    static boolean isUtf8(byte[] bytes, int offset, int length) {
        var end = offset + length;
        for (var i = offset; i < end; ) {
            var b = bytes[i] & 0xFF;
            if (b < 0x80) {
                i++;
                continue;
            }

            int count;
            int min;
            int codePoint;
            if (b >= 0xC2 && b <= 0xDF) {
                count = 1;
                min = 0x80;
                codePoint = b & 0x1F;
            } else if (b >= 0xE0 && b <= 0xEF) {
                count = 2;
                min = 0x800;
                codePoint = b & 0x0F;
            } else if (b >= 0xF0 && b <= 0xF4) {
                count = 3;
                min = 0x10000;
                codePoint = b & 0x07;
            } else {
                return false;
            }
            if (end - i <= count)
                return false;

            for (var k = 1; k <= count; k++) {
                var next = bytes[i + k] & 0xFF;
                if ((next & 0xC0) != 0x80)
                    return false;
                codePoint = (codePoint << 6) | (next & 0x3F);
            }
            if (codePoint < min || codePoint > 0x10FFFF || (codePoint >= 0xD800 && codePoint <= 0xDFFF))
                return false;
            i += count + 1;
        }
        return true;
    }

    /** One pull: the secrets read one after another, and what they held. */
    private final class Pull {
        final CompletableFuture<Void> result = new CompletableFuture<>();
        final AtomicReference<CompletableFuture<Void>> current = new AtomicReference<>();
        final Map<String, String> found = newValues();
        final Iterator<Map.Entry<String, List<SecretRequest>>> remaining = requests.entrySet().iterator();

        // Reads the remaining secrets, in a loop while each read completes at once, and from the
        // read's completion once one doesn't.
        void next() {
            while (!result.isDone()) {
                if (!remaining.hasNext()) {
                    finish();
                    return;
                }

                var secret = remaining.next();
                var values = newValues();
                CompletableFuture<Void> read;
                try {
                    read = Objects.requireNonNull(readSecretAsync(secret.getKey(), secret.getValue(), values), "readSecretAsync returned null");
                } catch (RuntimeException | Error e) {
                    result.completeExceptionally(e);
                    return;
                }

                current.set(read);
                if (result.isCancelled())
                    read.cancel(true);
                if (!read.isDone()) {
                    read.whenComplete((ignored, error) -> {
                        if (keep(read, secret.getValue(), values))
                            next();
                    });
                    return;
                }
                if (!keep(read, secret.getValue(), values))
                    return;
            }
        }

        // Keeps what a completed read found; false, the pull failed, if it failed.
        private boolean keep(CompletableFuture<Void> read, List<SecretRequest> secretRequests, Map<String, String> values) {
            try {
                read.join();
            } catch (RuntimeException e) {
                result.completeExceptionally(KeyWrapperFutures.unwrap(e));
                return false;
            }

            for (var request : secretRequests) {
                var value = values.get(request.fileName());
                if (value != null)
                    found.put(request.fileName(), value);
            }
            return true;
        }

        private void finish() {
            var missing = new ArrayList<String>();
            for (var secretRequests : requests.values()) {
                for (var request : secretRequests) {
                    if (!found.containsKey(request.fileName()))
                        missing.add(request.secretName());
                }
            }

            // Kept only by a pull nobody cancelled.
            if (result.isDone())
                return;
            writableProtectedSecrets.putAll(found);
            pulled = true;

            if (missing.isEmpty())
                result.complete(null);
            else
                result.completeExceptionally(new NoSuchElementException("The secret store holds no value for: " + String.join(", ", missing) + "."));
        }
    }
}
