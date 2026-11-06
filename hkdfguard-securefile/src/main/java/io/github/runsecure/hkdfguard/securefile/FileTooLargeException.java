package io.github.runsecure.hkdfguard.securefile;

import java.io.IOException;
import java.io.Serial;

/**
 * A file {@link TrustedFile} read is longer than its caller allows; no more than one byte past the
 * limit was read. The Java counterpart of the InvalidDataException .NET's TrustedFile throws for
 * such a file.
 */
public class FileTooLargeException extends IOException {
    @Serial
    private static final long serialVersionUID = 1L;

    /** @param message names the file and the limit it is over */
    public FileTooLargeException(String message) {
        super(message);
    }
}
