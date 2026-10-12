package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.util.Objects;
import java.util.function.Function;

/**
 * The three native KMS functions, bound through the FFM API - identical on every platform:
 * <pre>
 * int hkdfguard_wrap_dek(const char* service, const uint8_t* dek, int dek_len, uint8_t* out, int* out_len);
 * int hkdfguard_unwrap_dek(const char* service, const uint8_t* wrapped, int wrapped_len, uint8_t* out, int* out_len);
 * int hkdfguard_generate_and_wrap_dek(const char* service, uint8_t* out, int* out_len);
 * </pre>
 * Every argument is copied into native memory owned by one call, and every buffer that held key
 * material is zeroed before that memory is released. Native memory isn't moved by the garbage
 * collector, so this zeroing reaches the only native copy.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class KmsFunctions {
    private static final FunctionDescriptor WITH_INPUT = FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS);
    private static final FunctionDescriptor WITHOUT_INPUT = FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS);

    private final MethodHandle wrap;
    private final MethodHandle unwrap;
    private final MethodHandle generateAndWrap;

    private KmsFunctions(MethodHandle wrap, MethodHandle unwrap, MethodHandle generateAndWrap) {
        this.wrap = wrap;
        this.unwrap = unwrap;
        this.generateAndWrap = generateAndWrap;
    }

    /**
     * @param exports the address of a named export of the loaded library; throws if it has none
     */
    static KmsFunctions bind(Function<String, MemorySegment> exports) {
        var linker = Linker.nativeLinker();
        return new KmsFunctions(
                linker.downcallHandle(exports.apply("hkdfguard_wrap_dek"), WITH_INPUT),
                linker.downcallHandle(exports.apply("hkdfguard_unwrap_dek"), WITH_INPUT),
                linker.downcallHandle(exports.apply("hkdfguard_generate_and_wrap_dek"), WITHOUT_INPUT));
    }

    KmsResult wrapDek(String service, byte[] dek, byte[] destination) {
        return callWithInput(wrap, service, dek, destination);
    }

    KmsResult unwrapDek(String service, byte[] wrapped, byte[] destination) {
        return callWithInput(unwrap, service, wrapped, destination);
    }

    KmsResult generateAndWrapDek(String service, byte[] destination) {
        Objects.requireNonNull(service, "service");
        Objects.requireNonNull(destination, "destination");
        try (var arena = Arena.ofConfined()) {
            var serviceSegment = arena.allocateFrom(service);
            var output = arena.allocate(Math.max(1, destination.length));
            var outputLength = arena.allocateFrom(JAVA_INT, destination.length);
            try {
                var status = (int) generateAndWrap.invokeExact(serviceSegment, output, outputLength);
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
    // caller's buffer at all.
    private static KmsResult finish(int status, MemorySegment output, MemorySegment outputLength, byte[] destination) {
        var written = outputLength.get(JAVA_INT, 0);
        if (status == AbstractHkdfGuardKmsLibrary.OK) {
            var copied = Math.min(Math.max(written, 0), destination.length);
            MemorySegment.copy(output, JAVA_BYTE, 0, destination, 0, copied);
        }
        return new KmsResult(status, written);
    }
}
