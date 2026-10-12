package io.github.runsecure.hkdfguard.keywrapping.v1;

import java.io.Serial;

/**
 * The platform's native HkdfGuard KMS library is not installed where it is loaded from. The
 * message names the location(s); the library is never searched for anywhere else.
 */
public class NativeLibraryNotFoundException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;

    public NativeLibraryNotFoundException(String message) {
        super(message);
    }

    public NativeLibraryNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
