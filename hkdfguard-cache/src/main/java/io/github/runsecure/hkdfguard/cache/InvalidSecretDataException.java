package io.github.runsecure.hkdfguard.cache;

/**
 * A secret, or a secret store's response holding one, can't be trusted as it was read: a body that
 * isn't the JSON expected, is too large, or holds more than one value, or a secret's JSON object
 * naming a key twice. The Java counterpart of .NET's InvalidDataException for secrets. Its message
 * says where, never what: no part of a secret is ever quoted, nor is any cause chained that could.
 * Unchecked, like every other HkdfGuard exception, so it passes through a fetch unchanged.
 */
public class InvalidSecretDataException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public InvalidSecretDataException(String message) {
        super(message);
    }
}
