package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * What one native KMS call returned.
 *
 * @param status       {@link AbstractHkdfGuardKmsLibrary#OK}, or a negative, platform-specific error
 * @param bytesWritten on success, the bytes written to the destination; on a buffer-too-small
 *                     failure, the capacity required
 */
public record KmsResult(int status, int bytesWritten) {
}
