package io.github.runsecure.hkdfguard.abstractions;

import java.io.IOException;
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
 * secret. No key ring is involved: the protector's key is the only one, and it is handed to the
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

    /** Releases the writer's connection to the secret store; the protector is left as it is. */
    @Override
    void close();
}
