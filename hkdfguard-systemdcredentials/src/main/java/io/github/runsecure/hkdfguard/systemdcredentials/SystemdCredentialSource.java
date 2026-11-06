package io.github.runsecure.hkdfguard.systemdcredentials;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.function.ToIntFunction;

/**
 * A {@link ProtectedReadOnlyCache} over systemd credentials - for CertificateOptionsLoader's
 * password, say. A name is looked for first among the credentials systemd decrypted for this
 * service (LoadCredentialEncrypted=, in its in-memory credentials directory), then among the
 * encrypted credential files it was given, which systemd-creds decrypts by that name. Nothing is
 * cached: every lookup reads the credential again, into a {@link SystemdCredential} zeroed as soon
 * as it has been copied out. A name it doesn't have - or that can't be a credential's name - is
 * reported missing: decrypt returns 0. Names match exactly, as the files' names do.
 *
 * <p>The synchronous members block while systemd-creds runs; {@code decryptAsync} doesn't. A loaded
 * credential is read on the calling thread, and its future returned complete. Every failure of
 * {@code decryptAsync} - a null name included - completes its future exceptionally.
 */
public final class SystemdCredentialSource implements ProtectedReadOnlyCache {
    private final SystemdCredentials credentials;
    private final Map<String, String> encryptedFiles;
    private final String credentialsDirectory;

    /** A source over this service's loaded credentials alone, in {@value SystemdCredentials#CREDENTIALS_DIRECTORY_VARIABLE}. */
    public SystemdCredentialSource() {
        this(null, null, null);
    }

    /**
     * A source over loaded credentials, then encrypted credential files.
     *
     * @param credentials          decrypts the encrypted files; {@code null} when there are none
     * @param encryptedFiles       encrypted credential files by credential name, absolute paths; {@code null} for none
     * @param credentialsDirectory the service's credentials directory; {@code null} for
     *                             {@value SystemdCredentials#CREDENTIALS_DIRECTORY_VARIABLE}
     * @throws IllegalArgumentException encryptedFiles holds a name that isn't one, or a path that
     *                                  isn't absolute; or names files but credentials is null
     */
    public SystemdCredentialSource(SystemdCredentials credentials, Map<String, String> encryptedFiles, String credentialsDirectory) {
        var files = encryptedFiles == null ? Map.<String, String>of() : encryptedFiles;
        for (var entry : files.entrySet()) {
            if (!SystemdCredentials.isValidName(entry.getKey()))
                throw new IllegalArgumentException("'" + entry.getKey() + "' isn't a credential name.");
            if (!SystemdCredentials.isAbsolute(entry.getValue()))
                throw new IllegalArgumentException("The credential file for '" + entry.getKey() + "' must be an absolute path, not '" + entry.getValue() + "'.");
        }
        if (!files.isEmpty() && credentials == null)
            throw new IllegalArgumentException("Encrypted credential files need a SystemdCredentials to decrypt them.");

        this.credentials = credentials;
        this.encryptedFiles = Map.copyOf(new HashMap<>(files));
        this.credentialsDirectory = credentialsDirectory;
    }

    /**
     * @throws IllegalArgumentException result is too small for the value
     * @throws IllegalStateException    systemd-creds failed
     */
    @Override
    public int decrypt(String name, byte[] result) {
        return read(name, credential -> credential.copyTo(result));
    }

    /**
     * @throws IllegalArgumentException result is too small for the value
     * @throws IllegalStateException    systemd-creds failed
     */
    @Override
    public int decrypt(String name, char[] result) {
        return read(name, credential -> credential.decodeTo(result));
    }

    /** The credential file's length: never less than its value's, in bytes or in chars. */
    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        var path = locate(name);
        if (path == null)
            return OptionalInt.empty();
        try {
            var length = (int) Math.min(Files.size(path), Integer.MAX_VALUE);
            return length > 0 ? OptionalInt.of(length) : OptionalInt.empty();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public CompletableFuture<Integer> decryptAsync(String name, byte[] result) {
        return readAsync(name, credential -> credential.copyTo(result));
    }

    @Override
    public CompletableFuture<Integer> decryptAsync(String name, char[] result) {
        return readAsync(name, credential -> credential.decodeTo(result));
    }

    // The file name's value comes from: the loaded credential if there is one, else its encrypted file.
    private Path locate(String name) {
        Objects.requireNonNull(name, "name");
        if (!SystemdCredentials.isValidName(name))
            return null;

        var loaded = SystemdCredentials.loadedCredentialPath(name, credentialsDirectory);
        if (loaded != null && Files.isRegularFile(loaded))
            return loaded;
        var encrypted = encryptedFiles.get(name);
        return encrypted != null && Files.isRegularFile(Path.of(encrypted)) ? Path.of(encrypted) : null;
    }

    private boolean isEncrypted(String name, Path path) {
        var encrypted = encryptedFiles.get(name);
        return encrypted != null && Path.of(encrypted).equals(path);
    }

    private int read(String name, ToIntFunction<SystemdCredential> copy) {
        var path = locate(name);
        if (path == null)
            return 0;
        SystemdCredential credential;
        if (isEncrypted(name, path)) {
            try {
                credential = credentials.decryptAsync(name, path.toString()).join();
            } catch (CompletionException e) {
                if (e.getCause() instanceof RuntimeException runtime)
                    throw runtime;
                throw e;
            }
        } else {
            credential = SystemdCredentials.readLoadedCredential(name, credentialsDirectory);
            if (credential == null)
                return 0;
        }
        try (credential) {
            return copy.applyAsInt(credential);
        }
    }

    private CompletableFuture<Integer> readAsync(String name, ToIntFunction<SystemdCredential> copy) {
        Path path;
        try {
            path = locate(name);
            if (path == null)
                return CompletableFuture.completedFuture(0);
            if (!isEncrypted(name, path))
                return CompletableFuture.completedFuture(read(name, copy));
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        CompletableFuture<SystemdCredential> decrypting;
        try {
            decrypting = credentials.decryptAsync(name, path.toString());
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        // A dependent of the run itself, never of what the caller holds, so the value is zeroed
        // however the caller's future ends; cancelling that cancels - kills - the run.
        var result = new CompletableFuture<Integer>();
        decrypting.whenComplete((credential, failure) -> {
            if (failure != null) {
                result.completeExceptionally(failure instanceof CompletionException && failure.getCause() != null ? failure.getCause() : failure);
                return;
            }
            try (credential) {
                if (!result.isDone())
                    result.complete(copy.applyAsInt(credential));
            } catch (RuntimeException e) {
                result.completeExceptionally(e);
            }
        });
        result.whenComplete((count, failure) -> {
            if (result.isCancelled())
                decrypting.cancel(true);
        });
        return result;
    }
}
