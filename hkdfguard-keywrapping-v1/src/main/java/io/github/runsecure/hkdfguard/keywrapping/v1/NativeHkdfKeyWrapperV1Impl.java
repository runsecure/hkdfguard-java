package io.github.runsecure.hkdfguard.keywrapping.v1;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.ServiceNames;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.KmsResult;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/**
 * Protects (wrap) a DEK, or reveals (unwrap) a previously wrapped one, via the current OS's native
 * HkdfGuard KMS library - a TPM2, Secure Enclave, or Platform Crypto Provider key held entirely
 * outside this process, identified only by a service name. The native library owns the KEK, the
 * wrapped payload's format, and its own key derivation. Since unwrap takes its wrapped payload as
 * an explicit argument, a single instance handles both directions, and any number of different
 * wrapped payloads sharing the same service name.
 * <p>
 * The native calls are local and synchronous: each method runs on the calling thread and returns
 * an already completed future, failed with a {@link CryptographicException} naming the native
 * status when the library reports an error. The native library itself is loaded and verified on
 * the first call; a missing or unverifiable library fails that call's future with
 * {@link NativeLibraryNotFoundException} or {@link SecurityException}.
 */
public final class NativeHkdfKeyWrapperV1Impl implements KeyWrapper {
    private final String serviceName;
    private final AbstractHkdfGuardKmsLibrary library;

    /**
     * @param serviceName identifies the KEK: 1-128 ASCII letters, digits or '.', not starting with
     *                    '.' and without ".." (see {@link ServiceNames})
     * @throws NullPointerException          serviceName is null
     * @throws IllegalArgumentException      serviceName breaks a ServiceNames rule
     * @throws UnsupportedOperationException there is no native KMS library for this platform
     */
    public NativeHkdfKeyWrapperV1Impl(String serviceName) {
        this(serviceName, NativeHost.library());
    }

    NativeHkdfKeyWrapperV1Impl(String serviceName, AbstractHkdfGuardKmsLibrary library) {
        // Checked here, before the name can ever reach native code.
        ServiceNames.requireValid(serviceName, "serviceName");
        this.serviceName = serviceName;
        this.library = Objects.requireNonNull(library, "library");
    }

    @Override
    public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
        return complete(() -> library.wrapDek(serviceName, plaintext, result), "wrap", null);
    }

    @Override
    public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
        // Whatever a failed call left in the DEK buffer is erased.
        return complete(() -> library.unwrapDek(serviceName, wrapped, result), "unwrap", result);
    }

    @Override
    public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
        return complete(() -> library.generateAndWrapDek(serviceName, result), "generate-and-wrap", null);
    }

    private CompletableFuture<Integer> complete(Supplier<KmsResult> call, String operation, byte[] zeroOnFailure) {
        try {
            var result = call.get();
            if (result.status() == AbstractHkdfGuardKmsLibrary.OK)
                return CompletableFuture.completedFuture(result.bytesWritten());

            ArrayUtility.zeroMemory(zeroOnFailure);
            // Name the platform's meaning when it is known - "-13" alone tells an operator nothing.
            var description = library.describeStatus(result.status());
            var meaning = description != null ? " (" + description + ")" : "";
            return CompletableFuture.failedFuture(new CryptographicException(
                    "Native KMS " + operation + " failed for service '" + serviceName + "' with status " + result.status() + meaning + "."));
        } catch (RuntimeException e) {
            ArrayUtility.zeroMemory(zeroOnFailure);
            return CompletableFuture.failedFuture(e);
        }
    }
}
