package io.github.runsecure.hkdfguard.abstractions;

import java.io.IOException;
import java.io.Serial;

/**
 * A key file was read, but what it holds can't be a wrapped key: it is empty or the wrong size,
 * holds what looks like an unwrapped key, or isn't a valid wrapped payload. The Java counterpart of
 * .NET's InvalidDataException for key files.
 */
public class InvalidKeyFileException extends IOException {
    @Serial
    private static final long serialVersionUID = 1L;

    /** @param message names the key file and why it was refused */
    public InvalidKeyFileException(String message) {
        super(message);
    }
}
