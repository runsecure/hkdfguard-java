package io.github.runsecure.hkdfguard.keywrapping.v1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.NativeTestEnvironment;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Real key wrapping and unwrapping against this platform's native KMS library. No native library
 * creates a KEK during wrap/unwrap, so these run against an operator-provisioned service:
 * <pre>
 * hkdfguard provision --service-name hkdfguard.integrationtest   (elevated on Windows; hkdfguard-v1-initialize on macOS)
 * HKDFGUARD_TEST_SERVICE=hkdfguard.integrationtest mvn verify
 * </pre>
 * On Windows and macOS the provisioned test KEK NativeTestEnvironment.DEFAULT_SERVICE_NAME is used
 * when present.
 * Without a service every test here is reported as skipped - never as passed. With one, a library
 * that is missing, fails verification, or misbehaves fails the run. The tests only use that
 * service's existing KEK; they never create or delete one.
 */
class NativeKeyWrappingIntegrationTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private String service;

    @BeforeEach
    void requireAProvisionedService() {
        service = NativeTestEnvironment.assumeService();
    }

    private static byte[] randomDek() {
        var dek = new byte[32];
        RANDOM.nextBytes(dek);
        return dek;
    }

    @Test
    void wrapAndUnwrap_RoundTripsA32ByteDek() throws Exception {
        var wrapper = new NativeHkdfKeyWrapperV1Impl(service);
        var dek = randomDek();
        var wrapped = new byte[512];

        int wrappedLength = wrapper.wrapAsync(dek.clone(), wrapped).get();

        assertTrue(wrappedLength > 0);
        assertFalse(Arrays.equals(Arrays.copyOf(wrapped, wrappedLength), dek));

        var unwrapped = new byte[32];
        int unwrappedLength = wrapper.unwrapAsync(Arrays.copyOf(wrapped, wrappedLength), unwrapped).get();

        assertEquals(32, unwrappedLength);
        assertArrayEquals(dek, unwrapped);
    }

    @Test
    void generateAndWrap_ProducesAValid32ByteDek_ThatUnwrapsTheSameEveryTime() throws Exception {
        var wrapper = new NativeHkdfKeyWrapperV1Impl(service);
        var wrapped = new byte[512];

        int wrappedLength = wrapper.generateAndWrapAsync(wrapped).get();
        assertTrue(wrappedLength > 0);
        var payload = Arrays.copyOf(wrapped, wrappedLength);

        var first = new byte[32];
        assertEquals(32, wrapper.unwrapAsync(payload, first).get());
        assertFalse(ArrayUtility.isNullOrEmpty(first));

        var second = new byte[32];
        assertEquals(32, wrapper.unwrapAsync(payload, second).get());
        assertArrayEquals(first, second);
    }

    @Test
    void serviceIsolation_APayloadWrappedForOneService_DoesNotUnwrapUnderAnother() throws Exception {
        // A second provisioned service exercises the "wrong KEK" path; without one, an
        // unprovisioned name exercises "no KEK". Either way the unwrap must fail and reveal nothing.
        var wrapperA = new NativeHkdfKeyWrapperV1Impl(service);
        var wrapperB = new NativeHkdfKeyWrapperV1Impl(NativeTestEnvironment.otherServiceName());
        var wrapped = new byte[512];
        int wrappedLength = wrapperA.wrapAsync(randomDek(), wrapped).get();

        var destination = new byte[32];
        var failure = assertThrows(ExecutionException.class, () -> wrapperB.unwrapAsync(Arrays.copyOf(wrapped, wrappedLength), destination).get());

        assertInstanceOf(CryptographicException.class, failure.getCause());
        assertArrayEquals(new byte[32], destination);
    }

    @Test
    void multipleKeysUnderTheSameService_WrapAndUnwrapIndependently() throws Exception {
        var wrapper = new NativeHkdfKeyWrapperV1Impl(service);
        var dek1 = randomDek();
        var dek2 = randomDek();
        var wrapped1 = new byte[512];
        var wrapped2 = new byte[512];

        int length1 = wrapper.wrapAsync(dek1.clone(), wrapped1).get();
        int length2 = wrapper.wrapAsync(dek2.clone(), wrapped2).get();

        var recovered1 = new byte[32];
        var recovered2 = new byte[32];
        assertEquals(32, wrapper.unwrapAsync(Arrays.copyOf(wrapped1, length1), recovered1).get());
        assertEquals(32, wrapper.unwrapAsync(Arrays.copyOf(wrapped2, length2), recovered2).get());
        assertArrayEquals(dek1, recovered1);
        assertArrayEquals(dek2, recovered2);
    }

    @Test
    void theBinding_DirectWrapAndUnwrap_ReturnsOkAndRecoversTheDek() {
        var library = NativeHost.library();
        var dek = randomDek();
        var wrapped = new byte[512];

        var wrap = library.wrapDek(service, dek, wrapped);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, wrap.status());
        assertTrue(wrap.bytesWritten() > 0);

        var recovered = new byte[32];
        var unwrap = library.unwrapDek(service, Arrays.copyOf(wrapped, wrap.bytesWritten()), recovered);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, unwrap.status());
        assertEquals(32, unwrap.bytesWritten());
        assertArrayEquals(dek, recovered);
    }

    @Test
    void theBinding_DirectGenerateAndWrap_ReturnsOkAndAPayloadThatUnwraps() {
        var library = NativeHost.library();
        var wrapped = new byte[512];

        var generate = library.generateAndWrapDek(service, wrapped);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, generate.status());
        assertTrue(generate.bytesWritten() > 0);

        var recovered = new byte[32];
        var unwrap = library.unwrapDek(service, Arrays.copyOf(wrapped, generate.bytesWritten()), recovered);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, unwrap.status());
        assertEquals(32, unwrap.bytesWritten());
        assertFalse(ArrayUtility.isNullOrEmpty(recovered));
    }

    @Test
    void theBinding_WrapIntoATooSmallBuffer_ReportsAnErrorAndTheRequiredCapacity() {
        var result = NativeHost.library().wrapDek(service, randomDek(), new byte[1]);

        assertTrue(result.status() < 0);
        assertTrue(result.bytesWritten() > 1);
    }

    @Test
    void theBinding_UnwrapIntoATooSmallBuffer_ReportsAnError() {
        var library = NativeHost.library();
        var wrapped = new byte[512];
        var wrap = library.wrapDek(service, randomDek(), wrapped);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, wrap.status());

        var result = library.unwrapDek(service, Arrays.copyOf(wrapped, wrap.bytesWritten()), new byte[1]);

        assertTrue(result.status() < 0);
    }

    @Test
    void theBinding_GenerateAndWrapIntoATooSmallBuffer_ReportsAnError() {
        assertTrue(NativeHost.library().generateAndWrapDek(service, new byte[1]).status() < 0);
    }

    @Test
    void theBinding_UnwrapOfACorruptedPayload_ReportsAnError_AndWritesNothing() {
        var library = NativeHost.library();
        var wrapped = new byte[512];
        var wrap = library.wrapDek(service, randomDek(), wrapped);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, wrap.status());

        var payload = Arrays.copyOf(wrapped, wrap.bytesWritten());
        payload[0] ^= (byte) 0xFF;
        payload[payload.length / 2] ^= (byte) 0xFF;

        var recovered = new byte[32];
        var result = library.unwrapDek(service, payload, recovered);

        assertTrue(result.status() < 0);
        assertArrayEquals(new byte[32], recovered);
    }
}
