package io.github.runsecure.hkdfguard.keywrapping.awskms;

import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/**
 * A fresh folder under the user's temp folder, named by its long path: Windows may report the temp
 * folder by an 8.3 short name ({@code C:\Users\RUNNER~1\...} on hosted runners), which key files
 * are never read through.
 */
final class WindowsTempDirectory implements AutoCloseable {
    private static String currentUserSid;

    private final Path path;

    WindowsTempDirectory() throws IOException {
        // toRealPath: every component's real (long) name.
        path = Files.createTempDirectory("hkdfguard-keys-").toRealPath();
    }

    /** Trusts the account running the tests, which owns, and may modify, its own temp folder. */
    static KeyFileTrust trustCurrentUser() {
        return KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(currentUserSid());
    }

    Path write(String name, byte[] contents) throws IOException {
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
    private static synchronized String currentUserSid() {
        if (currentUserSid != null)
            return currentUserSid;

        try {
            var whoami = Path.of(System.getenv("SystemRoot"), "System32", "whoami.exe").toString();
            var process = new ProcessBuilder(whoami, "/user", "/fo", "csv", "/nh").redirectErrorStream(true).start();
            var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            process.waitFor();
            // "DOMAIN\\name","S-1-5-21-..."
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
}
