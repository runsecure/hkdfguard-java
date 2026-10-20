package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ServiceNames;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The Linux native library's contract, through the verified loader and the binding, against the
 * real KEK provider - on a TPM host, provisioned by this repository's scripts/provision-linux-test-key.sh:
 * <pre>
 * sudo scripts/provision-linux-test-key.sh
 * HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 \
 * HKDFGUARD_TEST_SERVICE_OTHER=com.hkdfguard.integration.test.221.other \
 * ./mvnw verify
 * </pre>
 * (the first is NativeTestEnvironment.DEFAULT_SERVICE_NAME). Key files are written to
 * NativeTestEnvironment.createTempDirectory, a private directory the library trusts - never /tmp,
 * whose directories it refuses.
 * NativeKeyWrappingIntegrationTest covers what every platform shares; these pin down the exact
 * Linux status codes, the native library's own input checks (which Java validation normally keeps
 * it from seeing), its zeroing on failure, and the deployment path through hkdfguard. Skipped off
 * Linux, without the libhkdfguard1 package, or without a provisioned service; some tests also need
 * a second service, the policy's pinned-names allowlist, or /usr/bin/hkdfguard. Test names follow
 * the .NET port's LinuxNativeIntegrationTests and the Go port's TestLinuxNative_*.
 * <p>
 * The Java binding never copies a failed call's output back to the caller's array, so the native
 * library's own zeroing of its output buffer on failure is checked through {@link RawUnwrap}, which
 * calls hkdfguard_unwrap_dek directly with a pre-filled native buffer and reads back exactly what
 * the library left there.
 */
@EnabledOnOs(value = OS.LINUX, disabledReason = "Linux only.")
class LinuxNativeIntegrationTest {
    private static final int DEK_LENGTH = AbstractHkdfGuardKmsLibrary.DEK_LENGTH;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final LinuxHkdfGuardKmsLibrary LIBRARY = new LinuxHkdfGuardKmsLibrary();

    private String service;

    @BeforeEach
    void requireTheLibraryAndAProvisionedService() {
        service = NativeTestEnvironment.assumeLinuxNativeIntegration();
    }

    private static byte[] randomDek() {
        var dek = new byte[DEK_LENGTH];
        RANDOM.nextBytes(dek);
        return dek;
    }

    private static byte[] filled(int length) {
        var bytes = new byte[length];
        Arrays.fill(bytes, (byte) 0xAA);
        return bytes;
    }

    private static void assertZero(byte[] bytes, String what) {
        assertArrayEquals(new byte[bytes.length], bytes, what + " was not zeroed");
    }

    private byte[] wrap(byte[] dek) {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        var result = LIBRARY.wrapDek(service, dek, wrapped);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, result.status(), () -> "wrapDek: " + LIBRARY.describeStatus(result.status()));
        return Arrays.copyOf(wrapped, result.bytesWritten());
    }

    /** A status, and that the binding describes it. */
    private static void assertStatus(int expected, int actual) {
        assertEquals(expected, actual, () -> "status " + actual + " (" + LIBRARY.describeStatus(actual) + ")");
        assertNotNull(LIBRARY.describeStatus(actual), "status " + actual + " has no description");
    }

    @Test
    void aWrappedDek_RoundTrips_AndFitsTheKeyFileLimit() {
        var dek = randomDek();

        var wrapped = wrap(dek);
        var recovered = new byte[DEK_LENGTH];
        var result = LIBRARY.unwrapDek(service, wrapped, recovered);

        assertEquals(AbstractHkdfGuardKmsLibrary.OK, result.status());
        assertEquals(DEK_LENGTH, result.bytesWritten());
        assertArrayEquals(dek, recovered);
        assertTrue(wrapped.length > DEK_LENGTH && wrapped.length <= WrappedKeyLimits.MAX_BYTES, "payload is " + wrapped.length + " bytes");
    }

    @Test
    void wrappingTheSameDekTwice_GivesDifferentPayloads() {
        // A fresh salt per payload: equal DEKs must not be recognizable from their wrapped form.
        var dek = randomDek();

        assertFalse(Arrays.equals(wrap(dek), wrap(dek)));
    }

    @Test
    void generatedDeks_AreDistinct() {
        var deks = new HashSet<String>();
        for (var i = 0; i < 4; i++) {
            var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
            var generated = LIBRARY.generateAndWrapDek(service, wrapped);
            assertEquals(AbstractHkdfGuardKmsLibrary.OK, generated.status());

            var dek = new byte[DEK_LENGTH];
            assertEquals(AbstractHkdfGuardKmsLibrary.OK, LIBRARY.unwrapDek(service, Arrays.copyOf(wrapped, generated.bytesWritten()), dek).status());
            deks.add(HexFormat.of().formatHex(dek));
        }

        assertEquals(4, deks.size());
    }

    @Test
    void unwrappingUnderAnotherProvisionedService_IsAFingerprintMismatch_AndZeroesTheWholeBuffer() {
        var other = NativeTestEnvironment.assumeOtherService();
        var wrapped = wrap(randomDek());

        var raw = RawUnwrap.call(other, wrapped, filled(64));

        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH, raw.status());
        assertZero(raw.destination(), "the native destination");

        // And through the binding: the caller's buffer is never written on failure.
        var destination = filled(64);
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH, LIBRARY.unwrapDek(other, wrapped, destination).status());
        assertArrayEquals(filled(64), destination);
    }

    @Test
    void aServiceTheAllowlistDoesNotName_HasNoKek() {
        NativeTestEnvironment.assumePinnedNamesAllowlist();
        var unlisted = NativeTestEnvironment.UNPROVISIONED_SERVICE_NAME;

        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND, LIBRARY.wrapDek(unlisted, new byte[DEK_LENGTH], new byte[WrappedKeyLimits.MAX_BYTES]).status());
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND, LIBRARY.generateAndWrapDek(unlisted, new byte[WrappedKeyLimits.MAX_BYTES]).status());
        assertTrue(LIBRARY.describeStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND).contains("provision"));
    }

    @Test
    void changingAnyByteOfThePayload_IsRefused_AndRevealsNothing() {
        // Every byte is either ciphertext or bound into the AEAD's associated data and the HKDF
        // info, so no single-byte change may unwrap - to the original DEK or to any other. Each
        // refusal can cost a TPM ECDH, so this changes the first and last eight bytes and every
        // fifth byte between: a spread that lands in every field of the payload.
        var wrapped = wrap(randomDek());

        for (var i = 0; i < wrapped.length; i++) {
            if (!(i < 8 || i >= wrapped.length - 8 || i % 5 == 0))
                continue;
            var tampered = wrapped.clone();
            tampered[i] ^= 0x01;

            var raw = RawUnwrap.call(service, tampered, filled(DEK_LENGTH));

            // A changed header byte makes the payload malformed or of an unknown version; a changed
            // fingerprint routes it to no KEK; anything else fails authentication.
            var status = raw.status();
            var position = i;
            assertTrue(status == AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_AUTH_FAILED || status == AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED
                            || status == AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_UNSUPPORTED || status == AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH,
                    () -> "byte " + position + " of " + wrapped.length + ": status " + status);
            assertZero(raw.destination(), "the destination after changing byte " + i);
        }
    }

    @Test
    void aTruncatedOrExtendedPayload_IsRefused() {
        var wrapped = wrap(randomDek());
        var destination = new byte[DEK_LENGTH];

        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED, LIBRARY.unwrapDek(service, Arrays.copyOf(wrapped, wrapped.length - 1), destination).status());
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED, LIBRARY.unwrapDek(service, Arrays.copyOf(wrapped, wrapped.length + 1), destination).status());
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED, LIBRARY.unwrapDek(service, Arrays.copyOf(wrapped, 8), destination).status());
    }

    @Test
    void anEmptyPayload_IsRefused() {
        var status = LIBRARY.unwrapDek(service, new byte[0], new byte[DEK_LENGTH]).status();

        assertTrue(status == AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT || status == AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED, "status " + status);
    }

    @Test
    void aDekOfTheWrongLength_IsAnInvalidArgument() {
        for (var length : new int[] {0, 16, DEK_LENGTH - 1, DEK_LENGTH + 1, 64})
            assertStatus(AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT, LIBRARY.wrapDek(service, new byte[length], new byte[WrappedKeyLimits.MAX_BYTES]).status());
    }

    static Stream<String> invalidServiceNames() {
        return Stream.of("", ".leading.dot", "double..dot", "has space", "slash/inside", "dash-inside", "caf\u00e9", "a".repeat(129));
    }

    @ParameterizedTest
    @MethodSource("invalidServiceNames")
    void theNativeLibrary_ChecksServiceNamesItself(String invalid) {
        // Java's ServiceNames rule normally stops these before the boundary; the library must
        // refuse them on its own too, for every operation.
        assertFalse(ServiceNames.isValid(invalid));

        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, LIBRARY.wrapDek(invalid, new byte[DEK_LENGTH], new byte[WrappedKeyLimits.MAX_BYTES]).status());
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, LIBRARY.generateAndWrapDek(invalid, new byte[WrappedKeyLimits.MAX_BYTES]).status());
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, LIBRARY.unwrapDek(invalid, new byte[100], new byte[DEK_LENGTH]).status());
    }

    @Test
    void aServiceNameOfTheMaximumLength_IsAccepted() {
        // 128 characters is valid; with the allowlist it simply has no KEK, without one it may.
        var longest = "a".repeat(ServiceNames.MAX_LENGTH);

        var status = LIBRARY.wrapDek(longest, new byte[DEK_LENGTH], new byte[WrappedKeyLimits.MAX_BYTES]).status();

        assertNotEquals(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, status);
    }

    @Test
    void aTooSmallBuffer_ReportsACapacityThatSuffices() {
        // The reported capacity is an upper bound for any payload (276 bytes on 0.1.0, for a
        // 164-byte payload), not the exact size of this one; it must fit a key file and be enough.
        var dek = randomDek();

        var tooSmall = LIBRARY.wrapDek(service, dek, new byte[1]);
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL, tooSmall.status());
        var required = tooSmall.bytesWritten();
        assertTrue(required > DEK_LENGTH && required <= WrappedKeyLimits.MAX_BYTES, "required capacity " + required);

        var exact = new byte[required];
        var wrapped = LIBRARY.wrapDek(service, dek, exact);
        assertEquals(AbstractHkdfGuardKmsLibrary.OK, wrapped.status());
        assertTrue(wrapped.bytesWritten() > DEK_LENGTH && wrapped.bytesWritten() <= required, "wrote " + wrapped.bytesWritten() + " into " + required);
        exact = Arrays.copyOf(exact, wrapped.bytesWritten());

        var generate = LIBRARY.generateAndWrapDek(service, new byte[1]);
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL, generate.status());
        assertEquals(required, generate.bytesWritten());

        var raw = RawUnwrap.call(service, exact, filled(DEK_LENGTH - 1));
        assertStatus(AbstractHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL, raw.status());
        assertEquals(DEK_LENGTH, raw.bytesWritten());
        assertZero(raw.destination(), "the short destination");
    }

    @Test
    void concurrentCallers_EachGetTheirOwnDekBack() throws Exception {
        var tasks = new ArrayList<Callable<Boolean>>();
        for (var i = 0; i < 8; i++) {
            tasks.add(() -> {
                var dek = randomDek();
                var recovered = new byte[DEK_LENGTH];
                var status = LIBRARY.unwrapDek(service, wrap(dek), recovered).status();
                return status == AbstractHkdfGuardKmsLibrary.OK && Arrays.equals(dek, recovered);
            });
        }

        try (var executor = Executors.newFixedThreadPool(8)) {
            for (var result : executor.invokeAll(tasks))
                assertTrue(result.get());
        }
    }

    @Test
    void aKeyFileWrappedByTheProvisioningTool_RevealsItsDekThroughTheWrapper() throws Exception {
        // The deployment path: hkdfguard wraps a delivered DEK on the host, in its own process, and
        // the application unwraps the key file through this binding.
        NativeTestEnvironment.assumeLinuxCli();
        var directory = NativeTestEnvironment.createTempDirectory("hkdfguard-cli-");
        try {
            var ownerOnly = Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            var dek = randomDek();
            var dekFile = Files.createFile(directory.resolve("dek"), PosixFilePermissions.asFileAttribute(ownerOnly));
            Files.writeString(dekFile, Base64.getEncoder().encodeToString(dek), StandardCharsets.US_ASCII);
            var keyFile = directory.resolve("key.bin");

            var run = NativeTestEnvironment.runTool(NativeTestEnvironment.LINUX_CLI, "wrap", "--key-file-path", keyFile.toString(), "--service-name", service,
                    "--dek-file", dekFile.toString());
            assertEquals(0, run.exitCode(), () -> "hkdfguard wrap exited " + run.exitCode() + ": " + run.output());
            assertEquals(ownerOnly, Files.getPosixFilePermissions(keyFile));

            var wrapper = new NativeHkdfKeyWrapperV1Impl(service);
            var recovered = new byte[DEK_LENGTH];
            int written = wrapper.unwrapAsync(Files.readAllBytes(keyFile), recovered).get();

            assertEquals(DEK_LENGTH, written);
            assertArrayEquals(dek, recovered);

            // And read back as the application does, through hkdfguard_open_file.
            assertArrayEquals(Files.readAllBytes(keyFile), wrapper.readKeyFileAsync(keyFile).get());
        } finally {
            NativeTestEnvironment.deleteRecursively(directory);
        }
    }

    @Test
    void theProvisioningTool_ReportsTheTestServiceAsProvisioned() throws IOException, InterruptedException {
        NativeTestEnvironment.assumeLinuxCli();

        var run = NativeTestEnvironment.runTool(NativeTestEnvironment.LINUX_CLI, "provision", "--service-name", service);

        assertEquals(0, run.exitCode(), () -> "hkdfguard provision exited " + run.exitCode() + ": " + run.output());
    }

    /**
     * hkdfguard_unwrap_dek called directly on the library the verified loader loaded: the
     * destination's contents are copied into native memory first and copied back after the call
     * whatever its status, so a test sees exactly what the native library left in its buffer.
     */
    @SuppressWarnings("restricted") // Test-only native calls; the tests run with --enable-native-access.
    private static final class RawUnwrap {
        record Result(int status, int bytesWritten, byte[] destination) {
        }

        private static MethodHandle handle;

        private static synchronized MethodHandle handle() {
            if (handle == null) {
                var library = LinuxNativeLibraryLoader.load();
                handle = Linker.nativeLinker().downcallHandle(LinuxNativeLibraryLoader.export(library, "hkdfguard_unwrap_dek"),
                        FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS));
            }
            return handle;
        }

        static Result call(String service, byte[] wrapped, byte[] destination) {
            var unwrap = handle();
            try (var arena = Arena.ofConfined()) {
                var input = arena.allocate(Math.max(1, wrapped.length));
                MemorySegment.copy(wrapped, 0, input, JAVA_BYTE, 0, wrapped.length);
                var output = arena.allocate(Math.max(1, destination.length));
                MemorySegment.copy(destination, 0, output, JAVA_BYTE, 0, destination.length);
                var outputLength = arena.allocateFrom(JAVA_INT, destination.length);

                var status = (int) unwrap.invokeExact(arena.allocateFrom(service), input, wrapped.length, output, outputLength);

                var after = new byte[destination.length];
                MemorySegment.copy(output, JAVA_BYTE, 0, after, 0, after.length);
                output.fill((byte) 0);
                return new Result(status, outputLength.get(JAVA_INT, 0), after);
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Throwable t) {
                throw new IllegalStateException(t);
            }
        }
    }
}
