package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.util.Objects;
import java.util.function.Function;

/**
 * The native KMS functions, bound through the FFM API - identical on every platform:
 * <pre>
 * int hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int dek_len, uint8_t* out, int* out_len);
 * int hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int wrapped_len, uint8_t* out, int* out_len);
 * int hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int* out_len);
 * int hkdfguard_open_file(const char* path, uint8_t* out, int* out_len);
 * int hkdfguard_harden_process_with_flags(unsigned int flags);
 * </pre>
 * Every argument is copied into native memory owned by one call, and every buffer that held key
 * material is zeroed before that memory is released. Native memory isn't moved by the garbage
 * collector, so this zeroing reaches the only native copy.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class KmsFunctions {
    private static final FunctionDescriptor WITH_INPUT = FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS);
    private static final FunctionDescriptor WITHOUT_INPUT = FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS);
    // unsigned int is 32 bits on every supported platform; the flags never use the sign bit.
    private static final FunctionDescriptor WITH_FLAGS = FunctionDescriptor.of(JAVA_INT, JAVA_INT);

    private final MethodHandle wrap;
    private final MethodHandle unwrap;
    private final MethodHandle generateAndWrap;
    private final MethodHandle openFile;
    private final MethodHandle hardenProcess;

    private KmsFunctions(MethodHandle wrap, MethodHandle unwrap, MethodHandle generateAndWrap, MethodHandle openFile,
                         MethodHandle hardenProcess) {
        this.wrap = wrap;
        this.unwrap = unwrap;
        this.generateAndWrap = generateAndWrap;
        this.openFile = openFile;
        this.hardenProcess = hardenProcess;
    }

    /**
     * @param exports the address of a named export of the loaded library; throws if it has none
     */
    static KmsFunctions bind(Function<String, MemorySegment> exports) {
        var linker = Linker.nativeLinker();
        return new KmsFunctions(
                linker.downcallHandle(exports.apply("hkdfguard_wrap_dek"), WITH_INPUT),
                linker.downcallHandle(exports.apply("hkdfguard_unwrap_dek"), WITH_INPUT),
                linker.downcallHandle(exports.apply("hkdfguard_generate_and_wrap_dek"), WITHOUT_INPUT),
                // (const char* path, uint8_t* out, int* out_len): the same shape.
                linker.downcallHandle(exports.apply("hkdfguard_open_file"), WITHOUT_INPUT),
                linker.downcallHandle(exports.apply("hkdfguard_harden_process_with_flags"), WITH_FLAGS));
    }

    KmsResult wrapDek(String service, byte[] dek, byte[] destination) {
        return callWithInput(wrap, service, dek, destination);
    }

    KmsResult unwrapDek(String service, byte[] wrapped, byte[] destination) {
        return callWithInput(unwrap, service, wrapped, destination);
    }

    KmsResult generateAndWrapDek(String service, byte[] destination) {
        return callWithoutInput(generateAndWrap, service, destination);
    }

    /** {@code path} is passed as a NUL-terminated UTF-8 string. */
    KmsResult openFile(String path, byte[] destination) {
        return callWithoutInput(openFile, path, destination);
    }

    /** {@code flags} is a bitwise OR of the HKDFGUARD_HARDEN_* flags, or 0. */
    int hardenProcess(int flags) {
        try {
            return (int) hardenProcess.invokeExact(flags);
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("The native KMS call failed.", t);
        }
    }

    private static KmsResult callWithoutInput(MethodHandle function, String text, byte[] destination) {
        Objects.requireNonNull(text, "text");
        Objects.requireNonNull(destination, "destination");
        try (var arena = Arena.ofConfined()) {
            var textSegment = arena.allocateFrom(text);
            var output = arena.allocate(Math.max(1, destination.length));
            var outputLength = arena.allocateFrom(JAVA_INT, destination.length);
            try {
                var status = (int) function.invokeExact(textSegment, output, outputLength);
                return finish(status, output, outputLength, destination);
            } finally {
                output.fill((byte) 0);
            }
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("The native KMS call failed.", t);
        }
    }

    private static KmsResult callWithInput(MethodHandle function, String service, byte[] input, byte[] destination) {
        Objects.requireNonNull(service, "service");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(destination, "destination");
        try (var arena = Arena.ofConfined()) {
            var serviceSegment = arena.allocateFrom(service);
            var inputSegment = arena.allocate(Math.max(1, input.length));
            var output = arena.allocate(Math.max(1, destination.length));
            var outputLength = arena.allocateFrom(JAVA_INT, destination.length);
            try {
                MemorySegment.copy(input, 0, inputSegment, JAVA_BYTE, 0, input.length);
                var status = (int) function.invokeExact(serviceSegment, inputSegment, input.length, output, outputLength);
                return finish(status, output, outputLength, destination);
            } finally {
                inputSegment.fill((byte) 0);
                output.fill((byte) 0);
            }
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("The native KMS call failed.", t);
        }
    }

    // Copies the output back only on success: a failed call's partial output never reaches the
    // caller's buffer at all. A success claiming fewer than 0 or more than capacity bytes breaks the
    // native contract: both buffers are erased and the call fails, rather than return a count the
    // caller would trust.
    private static KmsResult finish(int status, MemorySegment output, MemorySegment outputLength, byte[] destination) {
        var written = outputLength.get(JAVA_INT, 0);
        if (status == AbstractHkdfGuardKmsLibrary.OK) {
            if (written < 0 || written > destination.length) {
                output.fill((byte) 0);
                ArrayUtility.zeroMemory(destination);
                throw new IllegalStateException("The native KMS call reported " + written + " bytes written into a "
                        + destination.length + "-byte buffer.");
            }
            MemorySegment.copy(output, JAVA_BYTE, 0, destination, 0, written);
        }
        return new KmsResult(status, written);
    }
}
