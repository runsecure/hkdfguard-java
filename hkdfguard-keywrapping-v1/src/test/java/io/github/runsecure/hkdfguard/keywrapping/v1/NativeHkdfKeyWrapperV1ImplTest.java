package io.github.runsecure.hkdfguard.keywrapping.v1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NativeHkdfKeyWrapperV1ImplTest {
    private static Throwable failureOf(CompletableFuture<?> future) {
        assertTrue(future.isDone(), "native calls complete synchronously");
        var thrown = assertThrows(ExecutionException.class, future::get);
        return thrown.getCause();
    }

    @Test
    void wrapAsync_DelegatesToTheLibrary() throws Exception {
        var library = new FakeHkdfGuardKmsLibrary();
        library.wrapPayloadToEmit = new byte[] {10, 20, 30, 40};
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.a", library);
        var plaintext = new byte[] {1, 2, 3, 4, 5};
        var result = new byte[16];

        var written = wrapper.wrapAsync(plaintext, result).get();

        assertEquals(4, written);
        assertEquals(1, library.wrapCallCount);
        assertEquals("service.a", library.lastService);
        assertArrayEquals(plaintext, library.lastWrapPlaintext);
        assertArrayEquals(new byte[] {10, 20, 30, 40}, Arrays.copyOf(result, 4));
    }

    @ParameterizedTest
    // Reserved codes: no platform returns them, so there is no meaning to add.
    @ValueSource(ints = {-7, -14, -40})
    void wrapAsync_WhenTheLibraryFails_FailsWithACryptographicExceptionNamingTheStatus(int status) {
        var library = new FakeHkdfGuardKmsLibrary();
        library.wrapDekStatus = status;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.d", library);

        var failure = assertInstanceOf(CryptographicException.class, failureOf(wrapper.wrapAsync(new byte[] {1, 2, 3}, new byte[8])));

        assertEquals("Native KMS wrap failed for service 'service.d' with status " + status + ".", failure.getMessage());
        assertEquals(1, library.wrapCallCount);
    }

    @Test
    void aFailureTheLibraryCanDescribe_NamesWhatTheStatusMeans() {
        var library = new FakeHkdfGuardKmsLibrary();
        library.unwrapDekStatus = -18;
        library.describe = status -> status == -18 ? "this account is not authorized to use the KEK" : null;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.d", library);

        var failure = failureOf(wrapper.unwrapAsync(new byte[] {1}, new byte[32]));

        assertEquals("Native KMS unwrap failed for service 'service.d' with status -18 (this account is not authorized to use the KEK).", failure.getMessage());
    }

    @Test
    void aFailure_NamesTheStatusAndItsSharedMeaning() {
        var library = new FakeHkdfGuardKmsLibrary();
        library.unwrapDekStatus = AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.d", library);

        var failure = failureOf(wrapper.unwrapAsync(new byte[] {1}, new byte[32]));

        assertEquals("Native KMS unwrap failed for service 'service.d' with status -17 "
                + "(no KEK is provisioned for this service; run hkdfguard provision).", failure.getMessage());
    }

    @Test
    void unwrapAsync_DelegatesToTheLibrary() throws Exception {
        var library = new FakeHkdfGuardKmsLibrary();
        library.unwrapPayloadToEmit = new byte[] {1, 2, 3, 4, 5};
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.a", library);
        var wrapped = new byte[] {10, 20, 30, 40};
        var result = new byte[16];

        var written = wrapper.unwrapAsync(wrapped, result).get();

        assertEquals(5, written);
        assertEquals(1, library.unwrapCallCount);
        assertEquals("service.a", library.lastService);
        assertArrayEquals(wrapped, library.lastUnwrapWrapped);
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, Arrays.copyOf(result, 5));
    }

    @ParameterizedTest
    // Reserved codes: no platform returns them, so there is no meaning to add.
    @ValueSource(ints = {-7, -14, -40})
    void unwrapAsync_WhenTheLibraryFails_FailsAndZeroesTheResultBuffer(int status) {
        var library = new FakeHkdfGuardKmsLibrary();
        library.unwrapDekStatus = status;
        library.unwrapGarbageOnFailure = new byte[] {9, 9, 9, 9};
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.d", library);
        var result = new byte[8];
        Arrays.fill(result, (byte) 0xFF);

        var failure = failureOf(wrapper.unwrapAsync(new byte[] {10, 20, 30}, result));

        assertEquals("Native KMS unwrap failed for service 'service.d' with status " + status + ".", failure.getMessage());
        assertEquals(1, library.unwrapCallCount);
        // Whatever the native call left in the DEK buffer before failing is gone.
        assertArrayEquals(new byte[8], result);
    }

    @Test
    void generateAndWrapAsync_DelegatesToTheLibrary() throws Exception {
        var library = new FakeHkdfGuardKmsLibrary();
        library.generateAndWrapPayloadToEmit = new byte[] {11, 22, 33, 44, 55};
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.e", library);
        var result = new byte[16];

        var written = wrapper.generateAndWrapAsync(result).get();

        assertEquals(5, written);
        assertEquals(1, library.generateAndWrapCallCount);
        assertEquals("service.e", library.lastService);
        assertArrayEquals(new byte[] {11, 22, 33, 44, 55}, Arrays.copyOf(result, 5));
    }

    @ParameterizedTest
    // Reserved codes: no platform returns them, so there is no meaning to add.
    @ValueSource(ints = {-7, -14, -40})
    void generateAndWrapAsync_WhenTheLibraryFails_FailsWithACryptographicException(int status) {
        var library = new FakeHkdfGuardKmsLibrary();
        library.generateAndWrapDekStatus = status;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.f", library);

        var failure = failureOf(wrapper.generateAndWrapAsync(new byte[16]));

        assertEquals("Native KMS generate-and-wrap failed for service 'service.f' with status " + status + ".", failure.getMessage());
        assertEquals(1, library.generateAndWrapCallCount);
    }

    @Test
    void aLibraryThatFailsToLoad_FailsTheFuture_RatherThanThrowing() {
        var library = new FakeHkdfGuardKmsLibrary();
        var refusal = new SecurityException("not signed by the HkdfGuard publisher");
        library.throwOnCall = refusal;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.g", library);
        var result = new byte[] {1, 2, 3};

        assertSame(refusal, failureOf(wrapper.unwrapAsync(new byte[] {1}, result)));
        assertSame(refusal, failureOf(wrapper.wrapAsync(new byte[32], new byte[64])));
        assertSame(refusal, failureOf(wrapper.generateAndWrapAsync(new byte[64])));
        assertArrayEquals(new byte[3], result);
    }

    // --- Key files: read through the native library ---------------------------------------------

    @Test
    void readKeyFileAsync_ReadsThroughTheNativeLibrary_NotJavaFileIo() throws Exception {
        var library = new FakeHkdfGuardKmsLibrary();
        library.openFilePayloadToEmit = new byte[132];
        for (var i = 0; i < 132; i++)
            library.openFilePayloadToEmit[i] = (byte) i;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.h", library);
        var path = Path.of("no", "such", "dek.bin");

        // The path doesn't exist: only the native library is asked about it.
        var read = wrapper.readKeyFileAsync(path).get();

        assertArrayEquals(library.openFilePayloadToEmit, read);
        assertEquals(1, library.openFileCallCount);
        assertEquals(path.toString(), library.lastOpenFilePath);
    }

    @Test
    void readKeyFileAsync_ThroughTheInterface_ReachesTheNativeLibrary() throws Exception {
        var library = new FakeHkdfGuardKmsLibrary();
        KeyWrapper wrapper = new NativeHkdfKeyWrapperV1Impl("service.h", library);

        wrapper.readKeyFileAsync(Path.of("dek.bin")).get();

        assertEquals(1, library.openFileCallCount);
    }

    @Test
    void readKeyFileAsync_SurfacesARefusalThroughTheReturnedFuture() {
        var library = new FakeHkdfGuardKmsLibrary();
        library.openFileStatus = AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.h", library);

        var failure = assertInstanceOf(InvalidKeyFileException.class, failureOf(wrapper.readKeyFileAsync(Path.of("dek.bin"))));

        assertTrue(failure.getMessage().contains("status -37"));
        assertTrue(failure.getMessage().contains("key exposure"));
    }

    @Test
    void readKeyFileAsync_SurfacesEachFileSystemRefusalAsItsJavaException() {
        var library = new FakeHkdfGuardKmsLibrary();
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.h", library);

        library.openFileStatus = AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND;
        assertInstanceOf(NoSuchFileException.class, failureOf(wrapper.readKeyFileAsync(Path.of("dek.bin"))));
        library.openFileStatus = AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED;
        assertInstanceOf(AccessDeniedException.class, failureOf(wrapper.readKeyFileAsync(Path.of("dek.bin"))));
    }

    @Test
    void readKeyFileAsync_AnEmptyOrNullPath_NeverReachesTheLibrary() {
        var library = new FakeHkdfGuardKmsLibrary();
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.h", library);

        assertInstanceOf(IllegalArgumentException.class, failureOf(wrapper.readKeyFileAsync(Path.of(""))));
        assertInstanceOf(NullPointerException.class, failureOf(wrapper.readKeyFileAsync(null)));
        assertEquals(0, library.openFileCallCount);
    }

    @Test
    void readKeyFileAsync_ALibraryThatFailsToLoad_FailsTheFuture() {
        var library = new FakeHkdfGuardKmsLibrary();
        var refusal = new SecurityException("not signed by the HkdfGuard publisher");
        library.throwOnCall = refusal;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.h", library);

        assertSame(refusal, failureOf(wrapper.readKeyFileAsync(Path.of("dek.bin"))));
    }

    // --- Service names: a bad one is rejected at construction, so it never reaches native code ----

    @ParameterizedTest
    @ValueSource(strings = {"", ".service", "my..service", "my-service"})
    void constructor_RejectsAnInvalidName_BeforeAnyNativeCall(String serviceName) {
        var library = new FakeHkdfGuardKmsLibrary();

        assertThrows(IllegalArgumentException.class, () -> new NativeHkdfKeyWrapperV1Impl(serviceName, library));

        assertEquals(0, library.totalCalls());
    }

    @Test
    void constructor_RejectsANullName() {
        assertThrows(NullPointerException.class, () -> new NativeHkdfKeyWrapperV1Impl(null, new FakeHkdfGuardKmsLibrary()));
    }

    @Test
    void constructor_RejectsAnOverlongName() {
        assertThrows(IllegalArgumentException.class, () -> new NativeHkdfKeyWrapperV1Impl("a".repeat(129), new FakeHkdfGuardKmsLibrary()));
    }

    @Test
    void thePublicConstructor_BindsThisPlatformsLibrary_WithoutLoadingIt() {
        assertNotNull(new NativeHkdfKeyWrapperV1Impl("test.service"));
    }
}
