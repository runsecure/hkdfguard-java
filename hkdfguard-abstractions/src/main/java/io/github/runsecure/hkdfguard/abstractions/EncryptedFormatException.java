package io.github.runsecure.hkdfguard.abstractions;

import java.io.Serial;

/**
 * A formatted encrypted value is malformed - the counterpart of .NET's FormatException, thrown by
 * {@link EncryptedFormatProvider} implementations. An {@link IllegalArgumentException}, as
 * {@link NumberFormatException} is.
 */
public class EncryptedFormatException extends IllegalArgumentException {
    @Serial
    private static final long serialVersionUID = 1L;

    public EncryptedFormatException(String message) {
        super(message);
    }
}
