package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * A binding that calls its platform's native KMS library through {@link KmsFunctions}, binding
 * them on the first call. A failed bind (library missing, or refused by verification) isn't
 * cached, so a fixed installation is picked up on the next call.
 */
abstract sealed class NativeKmsLibrary extends AbstractHkdfGuardKmsLibrary
        permits WindowsHkdfGuardKmsLibrary, LinuxHkdfGuardKmsLibrary, MacOsHkdfGuardKmsLibrary {
    private volatile KmsFunctions functions;

    /** Loads (and verifies) the platform's library and binds its functions. */
    protected abstract KmsFunctions bind();

    private KmsFunctions functions() {
        var bound = functions;
        if (bound != null)
            return bound;

        synchronized (this) {
            if (functions == null)
                functions = bind();
            return functions;
        }
    }

    @Override
    public final KmsResult wrapDek(String service, byte[] dek, byte[] destination) {
        return functions().wrapDek(service, dek, destination);
    }

    @Override
    public final KmsResult unwrapDek(String service, byte[] wrapped, byte[] destination) {
        return functions().unwrapDek(service, wrapped, destination);
    }

    @Override
    public final KmsResult generateAndWrapDek(String service, byte[] destination) {
        return functions().generateAndWrapDek(service, destination);
    }

    @Override
    protected final KmsResult openFileRaw(String path, byte[] destination) {
        return functions().openFile(path, destination);
    }
}
