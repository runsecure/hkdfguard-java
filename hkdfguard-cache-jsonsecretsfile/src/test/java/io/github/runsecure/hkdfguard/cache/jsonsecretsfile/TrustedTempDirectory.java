package io.github.runsecure.hkdfguard.cache.jsonsecretsfile;

import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.testsupport.WindowsTempDirectory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.Locale;
import java.util.UUID;

/**
 * A fresh folder the trust checks accept once {@link #trust()} trusts the current user: on Windows
 * a {@link WindowsTempDirectory} under the user's temp folder, by its long path; on Linux and macOS
 * one under this module's target folder, usable by its owner only - never under /tmp, which is
 * writable by everyone and so never trusted. hkdfguard-test-support can't hold this helper: it
 * returns a KeyFileTrust, and hkdfguard-securefile's own tests depend on hkdfguard-test-support.
 */
final class TrustedTempDirectory implements AutoCloseable {
    private final WindowsTempDirectory windows;
    private final Path path;
    private final KeyFileTrust trust;

    TrustedTempDirectory() throws IOException {
        if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")) {
            windows = new WindowsTempDirectory();
            path = windows.path();
            trust = KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(WindowsTempDirectory.currentUserSid());
            return;
        }

        windows = null;
        path = Files.createDirectory(Path.of("target", "trusted-" + UUID.randomUUID()).toAbsolutePath(),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        // This process just created the folder, so its owner and group are this process's effective
        // user and group.
        trust = KeyFileTrust.ADMINISTRATORS_ONLY
                .withUnixUserIds(((Number) Files.getAttribute(path, "unix:uid")).longValue())
                .withUnixGroupIds(((Number) Files.getAttribute(path, "unix:gid")).longValue());
    }

    Path path() {
        return path;
    }

    /** Trusts the current user, whose files these are. */
    KeyFileTrust trust() {
        return trust;
    }

    // Tolerates a test having removed the folder itself.
    @Override
    public void close() throws IOException {
        if (!Files.exists(path))
            return;

        if (windows != null) {
            windows.close();
            return;
        }
        try (var paths = Files.walk(path)) {
            for (var item : paths.sorted(Comparator.reverseOrder()).toList())
                Files.deleteIfExists(item);
        }
    }
}
