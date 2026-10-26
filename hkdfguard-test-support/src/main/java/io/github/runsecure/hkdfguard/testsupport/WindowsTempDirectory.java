package io.github.runsecure.hkdfguard.testsupport;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.nio.charset.StandardCharsets.UTF_16LE;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/**
 * A fresh folder under the user's temp folder for the Windows key-file tests of
 * hkdfguard-securefile and hkdfguard-keywrapping-awskms, named by its long path: Windows may report
 * the temp folder by an 8.3 short name ({@code C:\Users\RUNNER~1\...} on hosted runners), which key
 * files are never read through. The account running the tests owns, and may modify, its own temp
 * folder, so a test reading key files from here trusts {@link #currentUserSid()} as a deployer.
 */
@SuppressWarnings("restricted") // GetShortPathNameW, for the short-name test.
public final class WindowsTempDirectory implements AutoCloseable {
    private static String currentUserSid;

    private final Path path;

    public WindowsTempDirectory() throws IOException {
        // toRealPath: every component's real (long) name.
        path = Files.createTempDirectory("hkdfguard-keys-").toRealPath();
    }

    public Path path() {
        return path;
    }

    /** Writes {@code contents} to a new file {@code name} in this folder. */
    public Path write(String name, byte[] contents) throws IOException {
        return Files.write(path.resolve(name), contents);
    }

    @Override
    public void close() throws IOException {
        try (var paths = Files.walk(path)) {
            for (var item : paths.sorted(Comparator.reverseOrder()).toList())
                Files.deleteIfExists(item);
        }
    }

    /** The SID of the account running the tests, as {@code whoami /user} reports it. */
    public static synchronized String currentUserSid() {
        if (currentUserSid != null)
            return currentUserSid;

        try {
            var whoami = Path.of(System.getenv("SystemRoot"), "System32", "whoami.exe").toString();
            var process = new ProcessBuilder(whoami, "/user", "/fo", "csv", "/nh").redirectErrorStream(true).start();
            var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            process.waitFor();
            // "DOMAIN\name","S-1-5-21-..."
            var sid = output.substring(output.lastIndexOf(",\"") + 2, output.length() - 1);
            if (!sid.startsWith("S-1-"))
                throw new IllegalStateException("whoami reported no SID: " + output);
            return currentUserSid = sid;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** The path with each component's 8.3 short name, where the volume keeps them. */
    public static String shortPath(String longPath) {
        try (var arena = Arena.ofConfined()) {
            var linker = Linker.nativeLinker();
            var kernel32 = SymbolLookup.libraryLookup("kernel32.dll", arena);
            MethodHandle getShortPathName = linker.downcallHandle(kernel32.find("GetShortPathNameW").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
            var capacity = 1024;
            var buffer = arena.allocate(JAVA_CHAR, capacity);
            var length = (int) getShortPathName.invokeExact(arena.allocateFrom(longPath, UTF_16LE), buffer, capacity);
            return length > 0 && length < capacity ? buffer.getString(0, UTF_16LE) : longPath;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }
}
