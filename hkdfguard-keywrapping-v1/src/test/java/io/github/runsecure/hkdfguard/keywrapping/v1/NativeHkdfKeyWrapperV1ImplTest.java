package io.github.runsecure.hkdfguard.keywrapping.v1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
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
    @ValueSource(ints = {-1, -2, -7})
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
        library.unwrapDekStatus = -13;
        library.describe = status -> status == -13 ? "this account is not authorized to use the KEK" : null;
        var wrapper = new NativeHkdfKeyWrapperV1Impl("service.d", library);

        var failure = failureOf(wrapper.unwrapAsync(new byte[] {1}, new byte[32]));

        assertEquals("Native KMS unwrap failed for service 'service.d' with status -13 (this account is not authorized to use the KEK).", failure.getMessage());
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
    @ValueSource(ints = {-1, -2, -6})
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
    @ValueSource(ints = {-1, -3, -7})
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
