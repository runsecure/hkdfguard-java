package io.github.runsecure.hkdfguard.securefile;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.platform.unix.UnixFiles;
import io.github.runsecure.hkdfguard.platform.windows.WindowsAccessRules;
import io.github.runsecure.hkdfguard.platform.windows.WindowsSecurity;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * Reads a file only after its location passes the platform's checks (WindowsKeyFileChecks,
 * UnixKeyFileChecks) - the same symbolic-link, ownership and permission checks
 * {@link TrustedKeyFile} applies - but with none of a key file's rules about its contents: for
 * secret files, certificates and anything else that must come from where only the operating
 * system's administrators and {@link KeyFileTrust} principals could have put it. What the contents
 * must look like is the caller's to check.
 * <p>
 * The caller says how large the file may be. At most one byte past that is read, whatever the file
 * reports as its length, so a wrong path (a log, a device) can't make it read without end; the
 * buffer is allocated at that size up front, so keep it close to the largest file expected.
 * <p>
 * A trusted file is expected to be small and on a local drive, so it is read on the calling thread,
 * as {@link TrustedKeyFile} reads a key file, and the future returned is already complete. Windows,
 * Linux and Apple silicon Macs are supported; the application grants this module native access, as
 * for TrustedKeyFile.
 */
public final class TrustedFile {
    // The longest array the JVM reliably allocates (the JDK's own SOFT_MAX_ARRAY_LENGTH); the read
    // buffer is one byte longer than the limit.
    static final int MAX_ARRAY_LENGTH = Integer.MAX_VALUE - 8;

    private TrustedFile() {
    }

    /**
     * Reads the file at {@code path}, refusing it unless only the operating system's administrators
     * and {@code trust} could have written or replaced it, or if it is longer than {@code maxBytes}.
     * For contents that are not themselves secret - a value encrypted elsewhere, a public
     * certificate; use the overload that takes a parser for anything that is.
     *
     * @param path     the file's path, absolute or relative to the working directory
     * @param trust    who besides administrators is trusted; {@link KeyFileTrust#ADMINISTRATORS_ONLY} for no one
     * @param maxBytes the longest file accepted
     * @return completes with the file's contents, which may be empty; fails with a
     *         {@link java.nio.file.NoSuchFileException} (the file, or a folder in its path, doesn't
     *         exist), a {@link java.nio.file.AccessDeniedException} (this account may not read it,
     *         or its location isn't trusted), a {@link FileTooLargeException} (it is longer than
     *         maxBytes), another {@link IOException} (it can't be read, or another process has it
     *         open for writing), an {@link IllegalArgumentException} ({@code trust} names a
     *         principal that can't be trusted), or an {@link UnsupportedOperationException} (not
     *         Windows, Linux or an Apple silicon Mac)
     * @throws NullPointerException     path or trust is null
     * @throws IllegalArgumentException path is empty, or maxBytes isn't positive or is too large
     *                                  for one array
     */
    public static CompletableFuture<byte[]> readAsync(Path path, KeyFileTrust trust, int maxBytes) {
        validateArguments(path, trust, maxBytes);

        try (var file = openTrusted(path, trust)) {
            return CompletableFuture.completedFuture(readContents(file, file.path(), maxBytes));
        } catch (IOException | RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Reads the file at {@code path} as {@link #readAsync(Path, KeyFileTrust, int)} does and hands
     * the contents to {@code parse} - for contents that are themselves secret, such as a PKCS#12
     * store or a PEM private key. The buffer behind the read-only view parse is given is zeroed once
     * parse returns or throws, so parse must not keep the view, and should zero any copy it makes.
     *
     * @param path     the file's path, absolute or relative to the working directory
     * @param trust    who besides administrators is trusted; {@link KeyFileTrust#ADMINISTRATORS_ONLY} for no one
     * @param maxBytes the longest file accepted
     * @param parse    turns the contents, which may be empty, into the result
     * @return completes with what parse returned; fails as the other overload's does, or with what
     *         parse threw
     * @throws NullPointerException     path, trust or parse is null
     * @throws IllegalArgumentException path is empty, or maxBytes isn't positive or is too large
     *                                  for one array
     */
    public static <T> CompletableFuture<T> readAsync(Path path, KeyFileTrust trust, int maxBytes, Function<ByteBuffer, ? extends T> parse) {
        validateArguments(path, trust, maxBytes);
        Objects.requireNonNull(parse, "parse");

        try (var file = openTrusted(path, trust)) {
            return CompletableFuture.completedFuture(readContents(file, file.path(), maxBytes, parse));
        } catch (IOException | RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Opens {@code path} for reading once the platform's checks have passed, refusing it if another
     * process has it open for writing; while it's open, no one can open it for writing. Dispatches
     * to one platform's wiring; each is exercised by the real-file tests on its own platform.
     *
     * @throws java.nio.file.NoSuchFileException   the file, or a folder in its path, doesn't exist
     * @throws java.nio.file.AccessDeniedException this account may not read it, or its location isn't trusted
     * @throws IOException                         another process has it open for writing, or it can't be opened
     * @throws IllegalArgumentException            trust names a principal that can't be trusted
     * @throws UnsupportedOperationException       not Windows, Linux or an Apple silicon Mac
     */
    static OpenedFile openTrusted(Path path, KeyFileTrust trust) throws IOException {
        var os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.startsWith("windows"))
            return openWindows(path, trust);
        if (os.startsWith("linux") || os.startsWith("mac os x") || os.startsWith("macos") || os.startsWith("darwin"))
            return openUnix(path, trust);

        throw new UnsupportedOperationException("Trusted files are read on Windows, Linux and macOS only.");
    }

    /**
     * Reads at most one byte past {@code maxBytes} from {@code stream}, refusing a longer file, and
     * returns what was read. The read buffer is zeroed.
     *
     * @throws FileTooLargeException the contents are longer than maxBytes
     * @throws IOException           the stream could not be read
     */
    static byte[] readContents(InputStream stream, String path, int maxBytes) throws IOException {
        var buffer = new byte[maxBytes + 1];
        try {
            return Arrays.copyOf(buffer, readBounded(stream, buffer, path));
        } finally {
            ArrayUtility.zeroMemory(buffer);
        }
    }

    /**
     * Reads as {@link #readContents(InputStream, String, int)} does and returns what {@code parse}
     * makes of a read-only view of the contents; the buffer is zeroed whether parse returns or
     * throws, and parse isn't called for a file that is too long.
     *
     * @throws FileTooLargeException the contents are longer than maxBytes
     * @throws IOException           the stream could not be read
     */
    static <T> T readContents(InputStream stream, String path, int maxBytes, Function<ByteBuffer, ? extends T> parse) throws IOException {
        var buffer = new byte[maxBytes + 1];
        try {
            var total = readBounded(stream, buffer, path);
            return parse.apply(ByteBuffer.wrap(buffer, 0, total).slice().asReadOnlyBuffer());
        } finally {
            ArrayUtility.zeroMemory(buffer);
        }
    }

    private static void validateArguments(Path path, KeyFileTrust trust, int maxBytes) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(trust, "trust");
        if (path.toString().isEmpty())
            throw new IllegalArgumentException("path must not be empty.");
        if (maxBytes <= 0 || maxBytes >= MAX_ARRAY_LENGTH)
            throw new IllegalArgumentException("maxBytes must be from 1 to " + (MAX_ARRAY_LENGTH - 1) + "; it is " + maxBytes + ".");
    }

    // Fills buffer as far as the stream goes; buffer is one byte longer than the longest file
    // accepted, so filling it means the file is too long.
    private static int readBounded(InputStream stream, byte[] buffer, String path) throws IOException {
        Objects.requireNonNull(buffer, "buffer");
        var total = 0;
        int read;
        while (total < buffer.length && (read = stream.read(buffer, total, buffer.length - total)) > 0)
            total += read;

        if (total == buffer.length)
            throw new FileTooLargeException("'" + path + "' is larger than " + (buffer.length - 1) + " bytes, the most it may be.");
        return total;
    }

    // Wires the WindowsKeyFileChecks policy to real files; exercised by the Windows-only real-file tests.
    private static OpenedFile openWindows(Path path, KeyFileTrust trust) throws IOException {
        var trusted = WindowsKeyFileChecks.trustedPrincipals(trust, WindowsSecurity::canonicalSid);
        // A relative path is resolved against the working directory (user.dir), as every Java file
        // API resolves one, and then put in the form .NET's Path.GetFullPath gives it.
        var fullPath = WindowsNative.fullPath(path.toAbsolutePath().toString());
        WindowsKeyFileChecks.verifyPathForm(fullPath,
                fullPath.startsWith("\\\\") ? DriveType.NETWORK : WindowsNative.driveType(Path.of(fullPath).getRoot().toString()));

        // Read sharing only: refused if another process has it open for writing, and no one can
        // open it for writing while it's read.
        var file = WindowsNative.open(fullPath);
        try {
            WindowsKeyFileChecks.verifyFinalPath(fullPath, file.finalPath());

            // The file through its own handle; the folders by path, which the final-path check ties
            // to the folders it was opened through, and which no untrusted principal can then change.
            WindowsKeyFileChecks.verifyTrustedOnly(file.securityDescriptor(), fullPath, fullPath, WindowsAccessRules.GUARDED_RIGHTS, trusted,
                    WindowsSecurity::accountName);
            for (var folder = Path.of(fullPath).getParent(); folder != null; folder = folder.getParent()) {
                var name = folder.toString();
                var security = WindowsSecurity.securityDescriptorOf(name);
                if (folder.getParent() == null) {
                    WindowsKeyFileChecks.verifyTrustedOnly(security, fullPath, name, WindowsAccessRules.GUARDED_ROOT_RIGHTS, trusted,
                            WindowsSecurity::accountName);
                    break;
                }

                WindowsKeyFileChecks.verifyNotReparsePoint(WindowsSecurity.fileAttributes(name), fullPath, name);
                WindowsKeyFileChecks.verifyTrustedOnly(security, fullPath, name, WindowsAccessRules.GUARDED_RIGHTS, trusted, WindowsSecurity::accountName);
            }

            return new OpenedFile(fullPath, file, new InputStream() {
                @Override
                public int read() throws IOException {
                    var one = new byte[1];
                    return read(one, 0, 1) <= 0 ? -1 : one[0] & 0xFF;
                }

                @Override
                public int read(byte[] buffer, int offset, int length) throws IOException {
                    var count = file.read(buffer, offset, length);
                    return count == 0 && length > 0 ? -1 : count;
                }
            });
        } catch (IOException | RuntimeException e) {
            file.close();
            throw e;
        }
    }

    // Wires the UnixKeyFileChecks policy to real files; exercised by the Unix-only real-file tests.
    private static OpenedFile openUnix(Path path, KeyFileTrust trust) throws IOException {
        // The working directory is already a resolved path; resolveTrusted handles ".." itself.
        var text = path.toString();
        String absolute;
        if (text.startsWith("/")) {
            absolute = text;
        } else {
            var workingDirectory = System.getProperty("user.dir");
            absolute = workingDirectory.endsWith("/") ? workingDirectory + text : workingDirectory + "/" + text;
        }
        var resolved = UnixKeyFileChecks.resolveTrusted(absolute, trust, UnixFiles::statusOrNull, UnixFiles::readLink);

        var stream = Files.newInputStream(Path.of(resolved));
        return new OpenedFile(text, stream, stream);
    }

    /**
     * A file {@link #openTrusted} opened and checked: its contents, and the path to name it by in a
     * message (the full path on Windows, the path as given on Linux and macOS). Closing it closes
     * the file.
     */
    static final class OpenedFile extends InputStream {
        private final String path;
        private final Closeable file;
        private final InputStream contents;

        private OpenedFile(String path, Closeable file, InputStream contents) {
            this.path = path;
            this.file = file;
            this.contents = contents;
        }

        String path() {
            return path;
        }

        @Override
        public int read() throws IOException {
            return contents.read();
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            return contents.read(buffer, offset, length);
        }

        @Override
        public void close() throws IOException {
            file.close();
        }
    }
}
