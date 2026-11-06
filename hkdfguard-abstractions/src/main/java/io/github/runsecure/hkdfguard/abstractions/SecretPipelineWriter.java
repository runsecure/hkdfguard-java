package io.github.runsecure.hkdfguard.abstractions;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;

/**
 * The end of a provisioning pipeline that delivers secrets from a secret store as one encrypted file
 * per secret - the folder layout FilePerSecretCacheImpl reads at runtime - before a durable KEK
 * exists. An implementation is given the secrets to pull and a {@link PipelineDataProtector} when it
 * is created; {@link #pullSecretsAsync} reads each secret and encrypts it at once, bound to its file
 * name, keeping only the encrypted value; {@link #writeProtectedSecretFiles} then writes one file per
 * secret, or {@link #writeJsonSecrets} one JSON file of them all - and each also to a stream, as a
 * tar archive of the files or as the JSON, for a remote command's standard input. No key ring is involved: the protector's key is the only one, and it is handed to the
 * native platform's wrap process once the files are written.
 * <p>
 * The protector belongs to the caller and is never closed by the writer. Closing the writer
 * releases its connection to the secret store.
 */
public interface SecretPipelineWriter extends AutoCloseable {
    /**
     * Every secret pulled, by file name: its value encrypted by the protector and formatted, as its
     * file will hold it. Empty until {@link #pullSecretsAsync} completes. A read-only view, whose
     * file names match ignoring ASCII case.
     */
    Map<String, String> getProtectedSecrets();

    /**
     * Reads every secret the writer was created with and encrypts each value, keeping it in
     * {@link #getProtectedSecrets()} - replacing whatever an earlier pull kept. Cancel the returned
     * future to cancel the reads.
     *
     * @return completes once every secret has been read; fails with {@link NoSuchElementException}
     *         when a secret has no value, every other secret being kept
     */
    CompletableFuture<Void> pullSecretsAsync();

    /**
     * Writes every secret in {@link #getProtectedSecrets()} as a file in {@code folderPath},
     * creating the folder if it doesn't exist: the file named for it, holding its encrypted,
     * formatted value as UTF-8.
     *
     * @param folderPath the folder to write to, absolute or relative to the working directory
     * @throws NullPointerException     folderPath is null
     * @throws IllegalArgumentException folderPath is empty
     * @throws IllegalStateException    no pull has completed
     * @throws IOException              the folder or a file couldn't be written
     */
    void writeProtectedSecretFiles(Path folderPath) throws IOException;

    /**
     * Writes every secret in {@link #getProtectedSecrets()} to one JSON file at {@code filePath},
     * creating its folder if it doesn't exist: a single object with a member per secret, its file
     * name mapped to its encrypted, formatted value. A file already there is replaced.
     *
     * @param filePath the file to write, absolute or relative to the working directory
     * @throws NullPointerException     filePath is null
     * @throws IllegalArgumentException filePath is empty
     * @throws IllegalStateException    no pull has completed
     * @throws IOException              the folder or the file couldn't be written
     */
    void writeJsonSecrets(Path filePath) throws IOException;

    /**
     * Writes every secret in {@link #getProtectedSecrets()} to {@code destination} as a tar archive
     * of the files {@link #writeProtectedSecretFiles} would write - for a remote tar to unpack, e.g.
     * the stdin of {@code ssh -T host sudo -n tar -x --no-same-owner -f - -C folder}. destination is
     * flushed and left open: close it afterwards, so tar sees the end of its input. Cancel the
     * returned future to stop the write.
     *
     * @param destination where to write the archive: a process's standard input
     * @return completes once the archive has been written and flushed; fails with the
     *         {@link IOException} the stream fails with
     * @throws NullPointerException  destination is null
     * @throws IllegalStateException no pull has completed
     */
    CompletableFuture<Void> writeProtectedSecretFilesAsync(OutputStream destination);

    /**
     * Writes every secret in {@link #getProtectedSecrets()} to {@code destination} as the JSON
     * object {@link #writeJsonSecrets} would write - for a remote command to store, e.g. the stdin
     * of {@code ssh -T host sudo -n tee /etc/app/secrets.json}. destination is flushed and left
     * open: close it afterwards, so the remote command sees the end of its input. Cancel the
     * returned future to stop the write.
     *
     * @param destination where to write the JSON: a process's standard input
     * @return completes once the JSON has been written and flushed; fails with the
     *         {@link IOException} the stream fails with
     * @throws NullPointerException  destination is null
     * @throws IllegalStateException no pull has completed
     */
    CompletableFuture<Void> writeJsonSecretsAsync(OutputStream destination);

    /** Releases the writer's connection to the secret store; the protector is left as it is. */
    @Override
    void close();
}
