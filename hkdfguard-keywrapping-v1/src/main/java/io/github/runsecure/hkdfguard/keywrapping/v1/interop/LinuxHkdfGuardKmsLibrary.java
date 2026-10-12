package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;

/**
 * Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest available
 * provider on the host - TPM2 &gt; PKCS#11 &gt; external secret &gt; software &gt; ephemeral - to hold
 * the per-service KEK. Every native call returns a plain status code. Loaded by the dynamic
 * linker's default search, as the .NET library does.
 */
@SuppressWarnings("restricted") // Loads the library through the FFM API; the module requires --enable-native-access.
public final class LinuxHkdfGuardKmsLibrary extends NativeKmsLibrary {
    static final String LIBRARY_NAME = "HkdfGuardKeyProtectionLinux";

    public static final int ERR_INVALID_ARGUMENT = -1;
    public static final int ERR_BUFFER_TOO_SMALL = -2;
    public static final int ERR_PROVIDER_UNAVAILABLE = -3;
    public static final int ERR_PROVIDER_ERROR = -4;
    public static final int ERR_CRYPTO_ERROR = -5;
    public static final int ERR_INTERNAL_ERROR = -6;
    public static final int ERR_INVALID_UTF8 = -7;
    public static final int ERR_MISSING_SERVICE_NAME = -8;

    @Override
    protected KmsFunctions bind() {
        var fileName = System.mapLibraryName(LIBRARY_NAME);
        SymbolLookup library;
        try {
            library = SymbolLookup.libraryLookup(fileName, Arena.global());
        } catch (IllegalArgumentException e) {
            throw new NativeLibraryNotFoundException("The HkdfGuard native KMS library '" + fileName + "' could not be loaded.", e);
        }

        return KmsFunctions.bind(name -> library.find(name)
                .orElseThrow(() -> new IllegalStateException("'" + fileName + "' has no '" + name + "' export.")));
    }
}
