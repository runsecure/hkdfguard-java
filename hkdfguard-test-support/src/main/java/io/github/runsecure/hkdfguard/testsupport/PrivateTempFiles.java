package io.github.runsecure.hkdfguard.testsupport;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Temporary files and folders in the system temp folder that only the account running the tests can
 * use, stated explicitly rather than left to the platform's defaults: rw------- / rwx------ where
 * the file system has POSIX permissions (Linux, macOS), and otherwise (Windows) an ACL whose only
 * entry grants the account full control - an explicit ACL replaces what the temp folder would pass
 * down. Static analysis (SonarQube's S5443) flags temp files created without such an attribute.
 */
public final class PrivateTempFiles {
    private PrivateTempFiles() {
    }

    /** A new file only this account can use. */
    public static Path createFile(String prefix, String suffix) throws IOException {
        return Files.createTempFile(prefix, suffix, ownerOnly("rw-------", Set.of()));
    }

    /** A new folder only this account can use. */
    public static Path createDirectory(String prefix) throws IOException {
        return Files.createTempDirectory(prefix, ownerOnly("rwx------", Set.of(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT)));
    }

    private static FileAttribute<?> ownerOnly(String posixPermissions, Set<AclEntryFlag> inheritance) throws IOException {
        var fileSystem = FileSystems.getDefault();
        if (fileSystem.supportedFileAttributeViews().contains("posix"))
            return PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(posixPermissions));

        var account = fileSystem.getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
        var entry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(account)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .setFlags(inheritance)
                .build();
        return new FileAttribute<List<AclEntry>>() {
            @Override
            public String name() {
                return "acl:acl";
            }

            @Override
            public List<AclEntry> value() {
                return List.of(entry);
            }
        };
    }
}
