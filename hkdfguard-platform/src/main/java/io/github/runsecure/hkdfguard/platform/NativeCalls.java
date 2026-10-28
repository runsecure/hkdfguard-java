package io.github.runsecure.hkdfguard.platform;

import static java.nio.charset.StandardCharsets.UTF_16LE;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;

/**
 * The FFM plumbing every HkdfGuard binding of operating-system calls shares: binding an export,
 * turning what a downcall throws into an unchecked exception, and reading what a call returns.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
public final class NativeCalls {
    private static final Linker LINKER = Linker.nativeLinker();

    private NativeCalls() {
    }

    /**
     * A downcall handle for {@code library}'s export {@code name}.
     *
     * @param kind names the library in the error, e.g. "Windows" or "C library"
     * @throws UnsatisfiedLinkError the library has no such export
     */
    public static MethodHandle bind(SymbolLookup library, String kind, String name, FunctionDescriptor descriptor, Linker.Option... options) {
        var address = library.find(name).orElseThrow(() -> new UnsatisfiedLinkError(kind + " export '" + name + "' not found."));
        return LINKER.downcallHandle(address, descriptor, options);
    }

    /**
     * What a downcall threw, as an exception to throw: a RuntimeException as it is, an Error thrown
     * from here, anything else (only {@link MethodHandle#invokeExact}'s declared Throwable) wrapped
     * in an IllegalStateException with {@code message}.
     */
    public static RuntimeException rethrow(Throwable t, String message) {
        if (t instanceof RuntimeException runtime)
            return runtime;
        if (t instanceof Error error)
            throw error;
        return new IllegalStateException(message, t);
    }

    /** Whether a returned pointer is NULL. */
    public static boolean isNull(MemorySegment pointer) {
        return pointer.address() == 0;
    }

    /** The NUL-terminated UTF-16LE string (a Windows wide string) {@code pointer} points to. */
    public static String readWideString(MemorySegment pointer) {
        return pointer.reinterpret(Long.MAX_VALUE).getString(0, UTF_16LE);
    }
}
