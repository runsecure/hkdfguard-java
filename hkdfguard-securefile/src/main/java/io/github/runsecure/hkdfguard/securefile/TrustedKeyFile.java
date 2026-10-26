package io.github.runsecure.hkdfguard.securefile;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.platform.unix.UnixFiles;
import io.github.runsecure.hkdfguard.platform.windows.WindowsAccessRules;
import io.github.runsecure.hkdfguard.platform.windows.WindowsSecurity;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Reads a key file only after its location passes the platform's checks (WindowsKeyFileChecks,
 * UnixKeyFileChecks): the Java equivalent of the native library's {@code hkdfguard_open_file}, for
 * a {@link KeyWrapper#readKeyFileAsync} with no native library to read through - a network KMS's
 * key wrapper, say. The contents are then held to the same rules: 1 to
 * {@link WrappedKeyLimits#MAX_BYTES} bytes, never more than one byte past that read, and not
 * something that looks like an unwrapped key.
 * <p>
 * Windows, Linux and Apple silicon Macs are supported. The checks are system calls made through the
 * FFM API, so the application grants this module native access
 * ({@code --enable-native-access=io.github.runsecure.hkdfguard.securefile}, or {@code ALL-UNNAMED}
 * on the class path).
 */
public final class TrustedKeyFile {
    /** The length of an unwrapped DEK; a file this size is probably a plaintext key. */
    static final int PLAINTEXT_KEY_LENGTH = 32;

    // A 32-byte key as text is at most 64 hex digits; allow surrounding whitespace.
    static final int PLAINTEXT_TEXT_SCAN_LIMIT = 96;

    private TrustedKeyFile() {
    }

    /**
     * Reads the key file at {@code path}, still wrapped, refusing it unless only the operating
     * system's administrators and {@code trust} could have written or replaced it, and refusing
     * contents that aren't a wrapped key.
     * <p>
     * A key file is a few hundred bytes on a local drive, so it is read on the calling thread, like
     * the native key wrapper's, and the future returned is already complete.
     *
     * @param path  the key file's path, absolute or relative to the working directory
     * @param trust who besides administrators is trusted; {@link KeyFileTrust#ADMINISTRATORS_ONLY} for no one
     * @return completes with the file's contents; fails with a
     *         {@link java.nio.file.NoSuchFileException} (the file, or a folder in its path, doesn't
     *         exist), a {@link java.nio.file.AccessDeniedException} (this account may not read it,
     *         or its location isn't trusted), an {@link InvalidKeyFileException} (it is empty, too
     *         long, or holds what looks like an unwrapped key), another {@link IOException} (it
     *         can't be read, or another process has it open for writing), an
     *         {@link IllegalArgumentException} ({@code trust} names a principal that can't be
     *         trusted), or an {@link UnsupportedOperationException} (not Windows, Linux or an Apple
     *         silicon Mac)
     * @throws NullPointerException     path or trust is null
     * @throws IllegalArgumentException path is empty
     */
    public static CompletableFuture<byte[]> readAsync(Path path, KeyFileTrust trust) {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(trust, "trust");
        if (path.toString().isEmpty())
            throw new IllegalArgumentException("path must not be empty.");

        try {
            return CompletableFuture.completedFuture(read(path, trust));
        } catch (IOException | RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    // Dispatches to one platform's wiring; each is exercised by the real-file tests on its own platform.
    private static byte[] read(Path path, KeyFileTrust trust) throws IOException {
        var os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.startsWith("windows"))
            return readWindows(path, trust);
        if (os.startsWith("linux") || os.startsWith("mac os x") || os.startsWith("macos") || os.startsWith("darwin"))
            return readUnix(path, trust);

        throw new UnsupportedOperationException("Key files are read on Windows, Linux and macOS only.");
    }

    // Wires the WindowsKeyFileChecks policy to real files; exercised by the Windows-only real-file tests.
    private static byte[] readWindows(Path path, KeyFileTrust trust) throws IOException {
        var trusted = WindowsKeyFileChecks.trustedPrincipals(trust, WindowsSecurity::canonicalSid);
        // A relative path is resolved against the working directory (user.dir), as every Java file
        // API resolves one, and then put in the form .NET's Path.GetFullPath gives it.
        var fullPath = WindowsNative.fullPath(path.toAbsolutePath().toString());
        WindowsKeyFileChecks.verifyPathForm(fullPath,
                fullPath.startsWith("\\\\") ? DriveType.NETWORK : WindowsNative.driveType(Path.of(fullPath).getRoot().toString()));

        // Read sharing only: refused if another process has it open for writing, and no one can
        // open it for writing while it's read.
        try (var file = WindowsNative.open(fullPath)) {
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

            return readContents(new InputStream() {
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
            }, fullPath);
        }
    }

    // Wires the UnixKeyFileChecks policy to real files; exercised by the Unix-only real-file tests.
    private static byte[] readUnix(Path path, KeyFileTrust trust) throws IOException {
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

        try (var stream = Files.newInputStream(Path.of(resolved))) {
            return readContents(stream, text);
        }
    }

    /**
     * Reads at most one byte past {@link WrappedKeyLimits#MAX_BYTES} from {@code stream} - so a
     * wrong path (a log, a device) can't make startup allocate an unbounded buffer - and refuses an
     * empty file, one over the limit, and one that looks like an unwrapped key. Whatever is read is
     * zeroed once copied out or refused.
     *
     * @throws InvalidKeyFileException the contents are refused
     * @throws IOException             the stream could not be read
     */
    static byte[] readContents(InputStream stream, String path) throws IOException {
        var buffer = new byte[WrappedKeyLimits.MAX_BYTES + 1];
        try {
            var total = 0;
            int read;
            while (total < buffer.length && (read = stream.read(buffer, total, buffer.length - total)) > 0)
                total += read;

            if (total == 0)
                throw new InvalidKeyFileException("Key file '" + path + "' is empty.");
            if (total > WrappedKeyLimits.MAX_BYTES)
                throw new InvalidKeyFileException("Key file '" + path + "' is larger than " + WrappedKeyLimits.MAX_BYTES
                        + " bytes (WrappedKeyLimits.MAX_BYTES); a wrapped key never is.");
            if (looksLikePlaintextKey(buffer, total))
                throw new InvalidKeyFileException("Key file '" + path
                        + "' holds what looks like an unwrapped 32-byte key, not a wrapped one. Treat that key as exposed: replace it, and write key files with the key wrapper.");

            return Arrays.copyOf(buffer, total);
        } finally {
            ArrayUtility.zeroMemory(buffer);
        }
    }

    /**
     * The native library's test for a plaintext key written to disk: exactly 32 bytes, or a 32-byte
     * key as 64 hex digits or as base64 (standard or URL-safe, padded or not), with any surrounding
     * whitespace.
     *
     * @param contents the file's bytes
     * @param length   how many of them were read
     */
    static boolean looksLikePlaintextKey(byte[] contents, int length) {
        if (length == PLAINTEXT_KEY_LENGTH)
            return true;
        if (length > PLAINTEXT_TEXT_SCAN_LIMIT)
            return false;

        var start = 0;
        var end = length;
        while (start < end && isWhitespace(contents[start]))
            start++;
        while (end > start && isWhitespace(contents[end - 1]))
            end--;
        return isHexKey(contents, start, end) || isBase64Key(contents, start, end);
    }

    // " \t\r\n\v\f", as .NET trims.
    private static boolean isWhitespace(byte b) {
        return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == 0x0B || b == '\f';
    }

    private static boolean isHexKey(byte[] text, int start, int end) {
        if (end - start != PLAINTEXT_KEY_LENGTH * 2)
            return false;
        for (var i = start; i < end; i++) {
            var c = text[i];
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'))
                return false;
        }

        return true;
    }

    private static boolean isBase64Key(byte[] text, int start, int end) {
        // 32 bytes: 43 characters, then one '=' when padded.
        if (end - start == 44 && text[start + 43] == '=')
            end--;
        if (end - start != 43)
            return false;

        var urlSafe = false;
        var standard = false;
        for (var i = start; i < end; i++) {
            var c = text[i];
            if (c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
                continue;
            if (c == '+' || c == '/')
                standard = true;
            else if (c == '-' || c == '_')
                urlSafe = true;
            else
                return false;
        }

        return !(urlSafe && standard);
    }
}
