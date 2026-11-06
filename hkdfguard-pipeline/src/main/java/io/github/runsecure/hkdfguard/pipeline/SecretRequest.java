package io.github.runsecure.hkdfguard.pipeline;

/**
 * One secret name a {@link SecretPipelineWriterBase} pulls: what to read, and the file it is written
 * as.
 *
 * @param secretName the name as it was given, key and all
 * @param key        the key to read; null for the secret's whole value
 * @param fileName   the file it is written as, and the name its value is bound to
 */
public record SecretRequest(String secretName, String key, String fileName) {
}
