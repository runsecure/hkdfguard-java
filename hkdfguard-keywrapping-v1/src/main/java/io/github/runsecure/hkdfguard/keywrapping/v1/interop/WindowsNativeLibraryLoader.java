package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

/**
 * Loads the Windows native KMS library from its one installed location and nowhere else. This
 * library receives every plaintext DEK on unwrap and chooses every "random" DEK on
 * generate-and-wrap, so loading an impostor would hand over every key. A plain library load would
 * search the application directory and then PATH; this loader replaces that with six checks, all
 * of which must pass before the file is mapped:
 * <ol>
 * <li>The file exists at {@code %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll}. The Program Files
 * location comes from the Windows known-folder registry setting, which only an administrator can
 * change, not from the {@code ProgramFiles} environment variable.</li>
 * <li>No component of that path, from the file up to (not including) the drive root, is a reparse
 * point - a symlink or junction could redirect a trusted-looking path somewhere writable.</li>
 * <li>Every one of those components is owned by, and writable only by, SYSTEM, Administrators, or
 * TrustedInstaller. The drive root is held only to what could rename the folder beneath it: a
 * trusted owner, and delete-child or ACL rights for trusted principals alone.</li>
 * <li>The file carries a valid Authenticode signature issued to {@link #EXPECTED_PUBLISHER} for
 * code signing under HkdfGuard's Artifact Signing profile ({@link #EXPECTED_PROFILE_EKU}), whose
 * chain - as WinVerifyTrust validated it - ends at the pinned root {@link #EXPECTED_ROOT_SHA256}.</li>
 * <li>Its PE header - covered by that signature - marks it a DLL for this process's architecture,
 * which refuses the profile's other binaries, such as hkdfguard.exe renamed into
 * place.</li>
 * <li>Its version resource - also covered by that signature - is at least
 * {@link #MINIMUM_LIBRARY_VERSION}, so an older release, though genuinely signed, can't be put in
 * place of a current one.</li>
 * <li>No certificate in the signer's chain has been revoked. Checked last, network allowed, and
 * refused only when Windows definitively reports a revocation ({@link WindowsRevocationPolicy}): a
 * host that can't reach the revocation servers still loads the library.</li>
 * </ol>
 * The library's own dependencies are then resolved from System32 only. After loading, the module
 * Windows actually mapped must be the file that was verified ({@link #verifyLoadedModule}), or it
 * is released and refused. Any failed check throws;
 * there is deliberately no fallback and no override of the path.
 */
final class WindowsNativeLibraryLoader {
    static final String FILE_NAME = "HkdfGuard.dll";

    /**
     * The Authenticode signer subject the library must carry, in the form Windows formats a
     * certificate subject (most specific attribute first). The signing certificate is short-lived
     * and reissued frequently, so a thumbprint can't be pinned; the subject is identity-verified by
     * the issuing CA. A subject alone proves nothing, though, so the root and profile are pinned too.
     */
    static final String EXPECTED_PUBLISHER = "CN=Torin Blair, O=Torin Blair, L=Littleton, S=co, C=US";

    /**
     * SHA-256 of the root the signer's chain must end at: Microsoft Identity Verification Root
     * Certificate Authority 2020, the root of Azure Artifact Signing. Without it, any root trusted
     * on the machine - including one a non-administrator added to their own CurrentUser\Root
     * store - could vouch for {@link #EXPECTED_PUBLISHER}. Compared by hash, never by name.
     */
    static final String EXPECTED_ROOT_SHA256 = "5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270";

    /** The EKU identifying HkdfGuard's Artifact Signing certificate profile. */
    static final String EXPECTED_PROFILE_EKU = "1.3.6.1.4.1.311.97.492781510.305179978.413069662.611988563";

    /** The Code Signing EKU (id-kp-codeSigning), required of the leaf. */
    static final String CODE_SIGNING_EKU = "1.3.6.1.5.5.7.3.3";

    // SYSTEM, BUILTIN\Administrators, and NT SERVICE\TrustedInstaller's fixed service SID.
    private static final Set<String> TRUSTED_PRINCIPALS = Set.of(
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    // Any right that lets a principal change what this path loads: write or append data, delete
    // or rename (DELETE on the item, FILE_DELETE_CHILD on its parent), write extended attributes,
    // or take over the ACL. Generic bits are listed too, since an ACE can carry them unmapped.
    private static final int FILE_WRITE_DATA = 0x0002;
    private static final int FILE_APPEND_DATA = 0x0004;
    private static final int FILE_WRITE_EA = 0x0010;
    private static final int FILE_DELETE_CHILD = 0x0040;
    private static final int DELETE = 0x00010000;
    private static final int WRITE_DAC = 0x00040000;
    private static final int WRITE_OWNER = 0x00080000;
    private static final int GENERIC_ALL = 0x10000000;
    private static final int GENERIC_WRITE = 0x40000000;

    static final int GUARDED_RIGHTS = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD | DELETE
            | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;

    // On the drive root, only what lets a principal rename or delete an entry directly beneath it -
    // delete-child, or taking over the ACL to grant it. Creating new entries there (Authenticated
    // Users may, on a default C:\) can't affect this path, and GENERIC_WRITE includes none of these.
    static final int GUARDED_ROOT_RIGHTS = FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

    // PE/COFF header values.
    static final int IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
    static final int IMAGE_FILE_DLL = 0x2000;
    static final int IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;
    static final int IMAGE_FILE_MACHINE_I386 = 0x014C;
    static final int IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    static final int IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

    private static MemorySegment handle;

    private WindowsNativeLibraryLoader() {
    }

    /** The single location the library is loaded from. */
    static String installedPath() {
        return Path.of(Win32.programFilesDirectory(), "HkdfGuard", "v1", FILE_NAME).toString();
    }

    /**
     * Verifies and loads the installed library, once per process; later calls return the same
     * handle. A failure isn't cached, so a fixed installation is picked up on the next call.
     *
     * @throws NativeLibraryNotFoundException the library isn't installed at {@link #installedPath()}
     * @throws SecurityException              the installed file or its location failed verification
     */
    static synchronized MemorySegment load() {
        if (handle == null)
            handle = load(installedPath(), EXPECTED_PUBLISHER);
        return handle;
    }

    static MemorySegment load(String path, String expectedPublisher) {
        if (!Files.isRegularFile(Path.of(path)))
            throw new NativeLibraryNotFoundException(
                    "The HkdfGuard native KMS library is not installed at '" + path + "'. Install it there; it is never loaded from anywhere else.");

        verifyLocation(path);
        verifySignature(path, expectedPublisher);
        verifyImageKind(path);
        verifyMinimumVersion(path, Win32.fileVersion(path));
        // Last, once everything else has passed: refused only if a certificate in the chain is
        // definitively revoked; unreachable revocation servers let the load continue.
        WindowsRevocationPolicy.verify(path, Win32.checkRevocation(path));

        // Absolute path, so no probing for the library itself; its own imports (kernel32,
        // advapi32, ncrypt) come from System32 only.
        var absolutePath = Path.of(path).toAbsolutePath().toString();
        var library = Win32.loadLibrary(absolutePath);
        try {
            verifyLoadedModule(absolutePath, Win32.moduleFileName(library));
            return library;
        } catch (RuntimeException e) {
            Win32.freeLibrary(library);
            throw e;
        }
    }

    /**
     * The oldest Windows native library release this package loads, {major, minor, patch}: 0.9.0,
     * the first to carry a version resource. Raise it when a release fixes a security issue.
     */
    static final int[] MINIMUM_LIBRARY_VERSION = {0, 9, 0};

    /**
     * Refuses a library whose file version - {major, minor, patch} from its signed version
     * resource, or null if it has none or it can't be read - is below
     * {@link #MINIMUM_LIBRARY_VERSION}. The fourth (revision) field is not compared. Run after
     * {@link #verifySignature}, whose hash covers the resource.
     *
     * @throws SecurityException no version, or an older one
     */
    static void verifyMinimumVersion(String path, int[] version) {
        var minimum = formatVersion(MINIMUM_LIBRARY_VERSION);
        if (version == null)
            throw new SecurityException("'" + path + "' carries no readable version resource, so it predates " + minimum
                    + ", the oldest HkdfGuard native library this package accepts; install a current release.");
        if (java.util.Arrays.compare(version, MINIMUM_LIBRARY_VERSION) < 0)
            throw new SecurityException("'" + path + "' is HkdfGuard native library version " + formatVersion(version)
                    + ", older than the minimum this package accepts (" + minimum + "); install a current release.");
    }

    private static String formatVersion(int[] version) {
        return version[0] + "." + version[1] + "." + version[2];
    }

    /**
     * Requires the file Windows mapped the loaded module from to be the verified path.
     * LoadLibraryExW returns an already-loaded module of the same name, and honours loader
     * redirection (.local, manifests), without mapping the path it was given; this is the Windows
     * counterpart of the dladdr check on Linux and macOS. The comparison is case-insensitive, as
     * NTFS names are, and ignores a {@code \\?\} prefix.
     *
     * @throws SecurityException Windows loaded some other file
     */
    static void verifyLoadedModule(String verified, String loaded) {
        if (!stripLongPathPrefix(loaded).equalsIgnoreCase(stripLongPathPrefix(verified)))
            throw new SecurityException("'" + verified + "' passed verification, but Windows loaded '" + loaded
                    + "' instead (a module of the same name was already loaded, or the load was redirected); refusing to use it.");
    }

    private static String stripLongPathPrefix(String path) {
        if (path.regionMatches(true, 0, "\\\\?\\UNC\\", 0, 8))
            return "\\\\" + path.substring(8);
        return path.startsWith("\\\\?\\") ? path.substring(4) : path;
    }

    /**
     * The address of a named export of a library {@link #load()} returned.
     *
     * @throws IllegalStateException it has no such export
     */
    static MemorySegment export(MemorySegment library, String name) {
        var address = Win32.procAddress(library, name);
        if (address == null)
            throw new IllegalStateException("The HkdfGuard native KMS library has no '" + name + "' export.");
        return address;
    }

    // --- Location -------------------------------------------------------------------------------

    /**
     * Checks the file and each parent folder below the drive root: not a reparse point, and owned
     * and writable only by trusted principals. The drive root itself must be owned by a trusted
     * principal and let no one else rename or delete what's directly beneath it - delete-child on a
     * folder renames any child, whatever the child's own ACL says.
     *
     * @throws SecurityException a path component failed a check
     */
    static void verifyLocation(String path) {
        var item = Path.of(path).toAbsolutePath().normalize();
        while (item != null) {
            var parent = item.getParent();
            if (parent == null) {
                verifyDriveRoot(Win32.securityDescriptorOf(item.toString()), item.toString());
                break;
            }

            verifyNotReparsePoint(item.toString());
            verifyTrustedOnly(Win32.securityDescriptorOf(item.toString()), item.toString());
            item = parent;
        }
    }

    /** @throws SecurityException the item is a symbolic link or junction, or can't be examined */
    static void verifyNotReparsePoint(String path) {
        var attributes = Win32.fileAttributes(path);
        if (attributes == Win32.INVALID_FILE_ATTRIBUTES)
            throw new SecurityException("'" + path + "' could not be examined; the HkdfGuard native library is only loaded through a path that can be verified.");
        if ((attributes & Win32.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw new SecurityException("'" + path + "' is a symbolic link or junction; the HkdfGuard native library is only loaded through a real path.");
    }

    /**
     * Requires a trusted owner and no Allow entry granting any write right to anyone else.
     * Inherit-only entries don't apply to this item, and Deny entries can only remove access, so
     * both are ignored. A missing DACL grants everyone everything, and is refused.
     *
     * @throws SecurityException the owner is untrusted, or an untrusted principal can write
     */
    static void verifyTrustedOnly(Win32.SecurityDescriptorInfo security, String displayPath) {
        verifyTrustedOnly(security, displayPath, GUARDED_RIGHTS, Win32::accountName);
    }

    /** The drive root's form of {@link #verifyTrustedOnly}: only rights that could rename or delete an entry beneath it are refused. */
    static void verifyDriveRoot(Win32.SecurityDescriptorInfo security, String displayPath) {
        verifyTrustedOnly(security, displayPath, GUARDED_ROOT_RIGHTS, Win32::accountName);
    }

    /**
     * @param accountName the account a SID string maps to, or null - for describing principals
     */
    static void verifyTrustedOnly(Win32.SecurityDescriptorInfo security, String displayPath, int guardedRights,
                                  Function<String, String> accountName) {
        var owner = security.ownerSid();
        if (owner == null || !TRUSTED_PRINCIPALS.contains(owner))
            throw new SecurityException("'" + displayPath + "' is owned by " + describe(owner, accountName)
                    + "; the HkdfGuard native library is only loaded from a location owned by SYSTEM, Administrators, or TrustedInstaller.");

        if (security.grantsEveryoneFull())
            throw new SecurityException("'" + displayPath + "' has no DACL, which grants every user full control; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.");

        for (var ace : security.aces()) {
            switch (ace.type()) {
                case Win32.ACCESS_DENIED_ACE_TYPE, Win32.ACCESS_DENIED_OBJECT_ACE_TYPE,
                     Win32.ACCESS_DENIED_CALLBACK_ACE_TYPE, Win32.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE -> {
                    continue;
                }
                case Win32.ACCESS_ALLOWED_ACE_TYPE, Win32.ACCESS_ALLOWED_CALLBACK_ACE_TYPE -> {
                    if ((ace.flags() & Win32.INHERIT_ONLY_ACE) != 0)
                        continue;

                    if ((ace.mask() & guardedRights) != 0 && !TRUSTED_PRINCIPALS.contains(ace.sid()))
                        throw new SecurityException(String.format("'%s' grants 0x%08X to %s; the HkdfGuard native library is only loaded from a location that only SYSTEM, Administrators, or TrustedInstaller can modify.",
                                displayPath, ace.mask(), describe(ace.sid(), accountName)));
                }
                default -> {
                    // An allow-object ACE, or a type a DACL shouldn't hold: its trustee can't be
                    // read the plain way, so fail closed rather than guess what it grants.
                    if ((ace.flags() & Win32.INHERIT_ONLY_ACE) == 0)
                        throw new SecurityException(String.format("'%s' has an access control entry of type 0x%02X, which this check can't evaluate; refusing to load from it.",
                                displayPath, ace.type()));
                }
            }
        }
    }

    private static String describe(String sid, Function<String, String> accountName) {
        if (sid == null)
            return "an unknown principal";

        var name = accountName.apply(sid);
        return name == null ? sid : name + " (" + sid + ")";
    }

    // --- Signature ------------------------------------------------------------------------------

    /**
     * What {@link #verifySignature(String, String, Function)} checks, read from a signature
     * WinVerifyTrust has already accepted.
     *
     * @param leafSubject the signing certificate's subject, formatted as Windows formats it
     * @param leafEkuOids the signing certificate's EKU OIDs; empty if it has no EKU extension
     * @param rootSha256  the SHA-256 of the root certificate the chain ends at, as hex
     */
    record VerifiedSigner(String leafSubject, Collection<String> leafEkuOids, String rootSha256) {
    }

    /**
     * Requires a valid, trusted Authenticode signature whose signer passes
     * {@link #verifySignerIdentity} for {@code expectedPublisher}.
     *
     * @throws SecurityException the signature is missing, invalid, untrusted, or from another signer
     */
    static void verifySignature(String path, String expectedPublisher) {
        verifySignature(path, expectedPublisher, WindowsNativeLibraryLoader::readVerifiedSigner);
    }

    /**
     * @param readSigner verifies the signature and reads its signer; throws SecurityException if the
     *                   signature isn't valid and trusted
     * @throws SecurityException the signer couldn't be read, or failed a check; any other failure is
     *                           reported as this too
     */
    static void verifySignature(String path, String expectedPublisher, Function<String, VerifiedSigner> readSigner) {
        VerifiedSigner signer;
        try {
            signer = readSigner.apply(path);
        } catch (SecurityException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new SecurityException("Could not read the Authenticode signer of '" + path + "'; refusing to load it.", e);
        }

        verifySignerIdentity(path, signer.leafSubject(), signer.leafEkuOids(), signer.rootSha256(), expectedPublisher);
    }

    /**
     * The signer policy: the leaf is issued to {@code expectedPublisher}, carries the Code Signing
     * EKU and {@link #EXPECTED_PROFILE_EKU}, and its chain ends at {@link #EXPECTED_ROOT_SHA256}. The
     * chain's trust is WinVerifyTrust's to decide, not this.
     *
     * @throws SecurityException any requirement isn't met
     */
    static void verifySignerIdentity(String path, String leafSubject, Collection<String> leafEkuOids, String rootSha256, String expectedPublisher) {
        if (!expectedPublisher.equals(leafSubject))
            throw new SecurityException("'" + path + "' is signed by '" + leafSubject + "', not the expected HkdfGuard publisher '" + expectedPublisher + "'.");

        if (!EXPECTED_ROOT_SHA256.equalsIgnoreCase(rootSha256))
            throw new SecurityException("'" + path + "' is signed under a root with SHA-256 " + rootSha256
                    + ", not Microsoft Identity Verification Root Certificate Authority 2020 (" + EXPECTED_ROOT_SHA256 + "), which HkdfGuard is signed under.");

        if (!leafEkuOids.contains(CODE_SIGNING_EKU))
            throw new SecurityException("'" + path + "' is signed with a certificate not issued for code signing (no EKU " + CODE_SIGNING_EKU + ").");

        if (!leafEkuOids.contains(EXPECTED_PROFILE_EKU))
            throw new SecurityException("'" + path + "' is signed with a certificate not issued under HkdfGuard's Artifact Signing profile (no EKU "
                    + EXPECTED_PROFILE_EKU + ").");
    }

    /**
     * Verifies the signature with WinVerifyTrust and reads the signer from the chain it validated,
     * rather than building a second chain that might differ from it.
     *
     * @throws SecurityException the signature is missing, invalid, or untrusted
     */
    static VerifiedSigner readVerifiedSigner(String path) {
        var verification = Win32.verifyEmbeddedSignature(path);
        if (verification.status() != 0)
            throw new SecurityException(String.format("'%s' does not carry a valid, trusted Authenticode signature (WinVerifyTrust status 0x%08X).",
                    path, verification.status()));

        var leaf = Certificate.getInstance(verification.leafDer());
        var ekuOids = new ArrayList<String>();
        var extensions = leaf.getTBSCertificate().getExtensions();
        var eku = extensions == null ? null : ExtendedKeyUsage.fromExtensions(extensions);
        if (eku != null)
            for (KeyPurposeId usage : eku.getUsages())
                ekuOids.add(usage.getId());

        var digest = SHA256Digest.newInstance();
        var root = verification.rootDer();
        digest.update(root, 0, root.length);
        var hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return new VerifiedSigner(windowsSubjectName(leaf.getSubject()), List.copyOf(ekuOids), Hex.toHexString(hash).toUpperCase(Locale.ROOT));
    }

    /**
     * A distinguished name as Windows (and .NET's X509Certificate2.Subject) formats it: the most
     * specific attribute first, ", " between attributes, " + " within a multi-valued RDN, Windows'
     * short names (S for state, E for email), and values quoted when they hold a special character
     * - so the pinned {@link #EXPECTED_PUBLISHER} is the same string in every port.
     */
    static String windowsSubjectName(X500Name name) {
        var rdns = name.getRDNs();
        var formatted = new StringBuilder();
        for (var i = rdns.length - 1; i >= 0; i--) {
            if (!formatted.isEmpty())
                formatted.append(", ");

            var values = rdns[i].getTypesAndValues();
            for (var j = 0; j < values.length; j++) {
                if (j > 0)
                    formatted.append(" + ");
                formatted.append(attributeName(values[j])).append('=').append(quoteIfNeeded(attributeValue(values[j])));
            }
        }
        return formatted.toString();
    }

    private static String attributeName(AttributeTypeAndValue value) {
        return switch (value.getType().getId()) {
            case "2.5.4.3" -> "CN";
            case "2.5.4.4" -> "SN";
            case "2.5.4.5" -> "SERIALNUMBER";
            case "2.5.4.6" -> "C";
            case "2.5.4.7" -> "L";
            case "2.5.4.8" -> "S";
            case "2.5.4.9" -> "STREET";
            case "2.5.4.10" -> "O";
            case "2.5.4.11" -> "OU";
            case "2.5.4.12" -> "T";
            case "2.5.4.42" -> "G";
            case "2.5.4.43" -> "I";
            case "2.5.4.17" -> "PostalCode";
            case "1.2.840.113549.1.9.1" -> "E";
            case "0.9.2342.19200300.100.1.25" -> "DC";
            default -> "OID." + value.getType().getId();
        };
    }

    private static String attributeValue(AttributeTypeAndValue value) {
        return value.getValue() instanceof ASN1String text ? text.getString() : value.getValue().toString();
    }

    private static String quoteIfNeeded(String value) {
        var needsQuotes = value.isEmpty() || Character.isWhitespace(value.charAt(0)) || Character.isWhitespace(value.charAt(value.length() - 1));
        for (var i = 0; !needsQuotes && i < value.length(); i++)
            needsQuotes = ",+=\"\n<>#;".indexOf(value.charAt(i)) >= 0;

        return needsQuotes ? '"' + value.replace("\"", "\"\"") + '"' : value;
    }

    // --- Image kind -----------------------------------------------------------------------------

    /**
     * Requires the file's PE header to mark it a DLL built for this process's architecture. Run
     * after {@link #verifySignature(String, String)}, whose hash covers the header.
     *
     * @throws SecurityException it isn't, or the header can't be read
     */
    static void verifyImageKind(String path) {
        int characteristics;
        int machine;
        try (var channel = FileChannel.open(Path.of(path), StandardOpenOption.READ)) {
            var dosHeader = read(channel, 0, 64);
            if (dosHeader.getShort(0) != 0x5A4D) // "MZ"
                throw new IOException("no DOS header");

            var peOffset = dosHeader.getInt(0x3C);
            if (peOffset < 0)
                throw new IOException("invalid PE header offset");

            // "PE\0\0", then the COFF header: Machine u16 @4, ..., Characteristics u16 @22.
            var peHeader = read(channel, peOffset, 24);
            if (peHeader.getInt(0) != 0x00004550)
                throw new IOException("no PE signature");

            machine = Short.toUnsignedInt(peHeader.getShort(4));
            characteristics = Short.toUnsignedInt(peHeader.getShort(22));
        } catch (IOException | RuntimeException e) {
            throw new SecurityException("Could not read the PE header of '" + path + "'; refusing to load it.", e);
        }

        verifyImageKind(path, characteristics, machine, CpuArchitecture.current());
    }

    private static ByteBuffer read(FileChannel channel, long position, int length) throws IOException {
        var buffer = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
        while (buffer.hasRemaining()) {
            if (channel.read(buffer, position + buffer.position()) < 0)
                throw new IOException("file too short");
        }
        return buffer.flip();
    }

    /**
     * The policy half of {@link #verifyImageKind(String)}.
     *
     * @throws SecurityException not a DLL, or not for {@code processArchitecture}
     */
    static void verifyImageKind(String path, int characteristics, int machine, CpuArchitecture processArchitecture) {
        if ((characteristics & IMAGE_FILE_DLL) == 0)
            throw new SecurityException("'" + path + "' is signed by the HkdfGuard publisher but is not a DLL (an executable renamed into place?); refusing to load it.");

        var expected = switch (processArchitecture) {
            case X64 -> IMAGE_FILE_MACHINE_AMD64;
            case ARM64 -> IMAGE_FILE_MACHINE_ARM64;
            case X86 -> IMAGE_FILE_MACHINE_I386;
            default -> -1;
        };
        if (machine != expected)
            throw new SecurityException(String.format("'%s' is built for machine type 0x%04X, but this is a %s process; refusing to load it.",
                    path, machine, processArchitecture));
    }
}
