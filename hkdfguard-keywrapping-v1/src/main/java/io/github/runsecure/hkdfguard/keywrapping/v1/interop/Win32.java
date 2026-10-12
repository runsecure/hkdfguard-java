package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;
import static java.nio.charset.StandardCharsets.UTF_16LE;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The Win32 calls the Windows loader's checks rely on, bound through the FFM API: known-folder
 * lookup, file attributes, security descriptors and SIDs, WinVerifyTrust, and LoadLibraryExW /
 * GetProcAddress. kernel32 is a KnownDLL, always mapped from System32; every other system library
 * is loaded by its absolute System32 path, so nothing here can be planted in the application
 * directory or on PATH. Each library is bound only on first use, so this class is inert off
 * Windows. 64-bit Windows only - the only Windows the JDK still supports.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class Win32 {
    static final int INVALID_FILE_ATTRIBUTES = -1;
    static final int FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

    static final int ACCESS_ALLOWED_ACE_TYPE = 0x00;
    static final int ACCESS_DENIED_ACE_TYPE = 0x01;
    static final int ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06;
    static final int ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09;
    static final int ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A;
    static final int ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C;
    static final int INHERIT_ONLY_ACE = 0x08;

    private static final int LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;
    private static final int KF_FLAG_DONT_VERIFY = 0x4000;
    private static final int SE_FILE_OBJECT = 1;
    private static final int OWNER_SECURITY_INFORMATION = 0x1;
    private static final int DACL_SECURITY_INFORMATION = 0x4;
    private static final int SDDL_REVISION_1 = 1;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Linker.Option CAPTURE_LAST_ERROR = Linker.Option.captureCallState("GetLastError");
    private static final MemoryLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
    private static final VarHandle LAST_ERROR = CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));

    private Win32() {
    }

    // --- Binding ---------------------------------------------------------------------------

    private static MethodHandle bind(SymbolLookup library, String name, FunctionDescriptor descriptor, Linker.Option... options) {
        var address = library.find(name).orElseThrow(() -> new UnsatisfiedLinkError("Windows export '" + name + "' not found."));
        return LINKER.downcallHandle(address, descriptor, options);
    }

    private static SymbolLookup system32(String fileName) {
        return SymbolLookup.libraryLookup(Path.of(Kernel32.SYSTEM_DIRECTORY, fileName), Arena.global());
    }

    private static final class Kernel32 {
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
        static final MethodHandle GET_SYSTEM_DIRECTORY = bind(LIBRARY, "GetSystemDirectoryW", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle LOAD_LIBRARY_EX = bind(LIBRARY, "LoadLibraryExW", FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_INT), CAPTURE_LAST_ERROR);
        static final MethodHandle GET_PROC_ADDRESS = bind(LIBRARY, "GetProcAddress", FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle GET_FILE_ATTRIBUTES = bind(LIBRARY, "GetFileAttributesW", FunctionDescriptor.of(JAVA_INT, ADDRESS), CAPTURE_LAST_ERROR);
        static final MethodHandle LOCAL_FREE = bind(LIBRARY, "LocalFree", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final String SYSTEM_DIRECTORY = systemDirectory();
    }

    private static final class Shell32 {
        static final SymbolLookup LIBRARY = system32("shell32.dll");
        static final MethodHandle SH_GET_KNOWN_FOLDER_PATH = bind(LIBRARY, "SHGetKnownFolderPath", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS));
    }

    private static final class Ole32 {
        static final SymbolLookup LIBRARY = system32("ole32.dll");
        static final MethodHandle CO_TASK_MEM_FREE = bind(LIBRARY, "CoTaskMemFree", FunctionDescriptor.ofVoid(ADDRESS));
    }

    private static final class Advapi32 {
        static final SymbolLookup LIBRARY = system32("advapi32.dll");
        static final MethodHandle GET_NAMED_SECURITY_INFO = bind(LIBRARY, "GetNamedSecurityInfoW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle CONVERT_SDDL_TO_SD = bind(LIBRARY, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
        static final MethodHandle GET_SD_OWNER = bind(LIBRARY, "GetSecurityDescriptorOwner", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle GET_SD_DACL = bind(LIBRARY, "GetSecurityDescriptorDacl", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle GET_ACE = bind(LIBRARY, "GetAce", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle CONVERT_SID_TO_STRING = bind(LIBRARY, "ConvertSidToStringSidW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle CONVERT_STRING_TO_SID = bind(LIBRARY, "ConvertStringSidToSidW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle LOOKUP_ACCOUNT_SID = bind(LIBRARY, "LookupAccountSidW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    }

    private static final class WinTrust {
        static final SymbolLookup LIBRARY = system32("wintrust.dll");
        static final MethodHandle WIN_VERIFY_TRUST = bind(LIBRARY, "WinVerifyTrust", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle PROV_DATA_FROM_STATE_DATA = bind(LIBRARY, "WTHelperProvDataFromStateData", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle GET_PROV_SIGNER_FROM_CHAIN = bind(LIBRARY, "WTHelperGetProvSignerFromChain",
                FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT));
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException runtime)
            return runtime;
        if (t instanceof Error error)
            throw error;
        return new IllegalStateException("A Win32 call failed.", t);
    }

    private static boolean isNull(MemorySegment pointer) {
        return pointer.address() == 0;
    }

    private static String readWideString(MemorySegment pointer) {
        return pointer.reinterpret(Long.MAX_VALUE).getString(0, UTF_16LE);
    }

    private static void localFree(MemorySegment pointer) {
        if (isNull(pointer))
            return;
        try {
            var ignored = (MemorySegment) Kernel32.LOCAL_FREE.invokeExact(pointer);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // --- Paths and loading ------------------------------------------------------------------

    private static String systemDirectory() {
        try (var arena = Arena.ofConfined()) {
            var capacity = 1024;
            var buffer = arena.allocate(JAVA_CHAR, capacity);
            var length = (int) Kernel32.GET_SYSTEM_DIRECTORY.invokeExact(buffer, capacity);
            if (length <= 0 || length >= capacity)
                throw new IllegalStateException("GetSystemDirectoryW failed.");
            return buffer.getString(0, UTF_16LE);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * The Program Files folder, from the known-folder registry setting (only an administrator can
     * change it), never from the ProgramFiles environment variable.
     */
    static String programFilesDirectory() {
        try (var arena = Arena.ofConfined()) {
            // FOLDERID_ProgramFiles {905e63b6-c1bf-494e-b29c-65b732d3d21a}
            var folderId = guid(arena, 0x905e63b6, (short) 0xc1bf, (short) 0x494e,
                    new byte[] {(byte) 0xb2, (byte) 0x9c, 0x65, (byte) 0xb7, 0x32, (byte) 0xd3, (byte) 0xd2, 0x1a});
            var result = arena.allocate(ADDRESS);
            var hresult = (int) Shell32.SH_GET_KNOWN_FOLDER_PATH.invokeExact(folderId, KF_FLAG_DONT_VERIFY, MemorySegment.NULL, result);
            var path = result.get(ADDRESS, 0);
            try {
                if (hresult != 0)
                    throw new IllegalStateException(String.format("SHGetKnownFolderPath(ProgramFiles) failed with HRESULT 0x%08X.", hresult));
                return readWideString(path);
            } finally {
                Ole32.CO_TASK_MEM_FREE.invokeExact(path);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** GetFileAttributesW: the item's own attributes (a link is not followed), or {@link #INVALID_FILE_ATTRIBUTES}. */
    static int fileAttributes(String path) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            return (int) Kernel32.GET_FILE_ATTRIBUTES.invokeExact(capture, arena.allocateFrom(path, UTF_16LE));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * LoadLibraryExW of an absolute path, with the library's own dependencies resolved from
     * System32 only - never the application directory or PATH. Never unloaded.
     *
     * @throws IllegalStateException the load failed
     */
    static MemorySegment loadLibrary(String absolutePath) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var handle = (MemorySegment) Kernel32.LOAD_LIBRARY_EX.invokeExact(capture, arena.allocateFrom(absolutePath, UTF_16LE),
                    MemorySegment.NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (isNull(handle))
                throw new IllegalStateException("LoadLibraryExW('" + absolutePath + "') failed with error " + (int) LAST_ERROR.get(capture, 0L) + ".");
            return handle;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** GetProcAddress: the export's address, or null if the module has no such export. */
    static MemorySegment procAddress(MemorySegment module, String name) {
        try (var arena = Arena.ofConfined()) {
            var address = (MemorySegment) Kernel32.GET_PROC_ADDRESS.invokeExact(module, arena.allocateFrom(name));
            return isNull(address) ? null : address;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // --- Security descriptors ---------------------------------------------------------------

    /** One ACE: its type, flags, access mask, and trustee SID (null for an ACE type with no plain SID). */
    record Ace(int type, int flags, int mask, String sid) {
    }

    /**
     * An item's owner and DACL.
     *
     * @param ownerSid           the owner's SID string, or null if the descriptor has no owner
     * @param grantsEveryoneFull true when there is no DACL (or a NULL one), which grants everyone full access
     * @param aces               the DACL's entries, in order
     */
    record SecurityDescriptorInfo(String ownerSid, boolean grantsEveryoneFull, List<Ace> aces) {
    }

    /**
     * The owner and DACL of a file or directory, read without following a link.
     *
     * @throws SecurityException the descriptor could not be read
     */
    static SecurityDescriptorInfo securityDescriptorOf(String path) {
        try (var arena = Arena.ofConfined()) {
            var owner = arena.allocate(ADDRESS);
            var dacl = arena.allocate(ADDRESS);
            var descriptor = arena.allocate(ADDRESS);
            var error = (int) Advapi32.GET_NAMED_SECURITY_INFO.invokeExact(arena.allocateFrom(path, UTF_16LE), SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, owner, MemorySegment.NULL, dacl, MemorySegment.NULL, descriptor);
            if (error != 0)
                throw new SecurityException("Could not read the security descriptor of '" + path + "' (error " + error + "); refusing to load from it.");

            var sd = descriptor.get(ADDRESS, 0);
            try {
                return parse(sd);
            } finally {
                localFree(sd);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * A security descriptor written in SDDL - for testing the policy against descriptors a real
     * folder would be hard to give.
     *
     * @throws IllegalArgumentException the SDDL is invalid
     */
    static SecurityDescriptorInfo securityDescriptorFromSddl(String sddl) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var descriptor = arena.allocate(ADDRESS);
            var ok = (int) Advapi32.CONVERT_SDDL_TO_SD.invokeExact(capture, arena.allocateFrom(sddl, UTF_16LE), SDDL_REVISION_1,
                    descriptor, MemorySegment.NULL);
            if (ok == 0)
                throw new IllegalArgumentException("Invalid SDDL (error " + (int) LAST_ERROR.get(capture, 0L) + "): " + sddl);

            var sd = descriptor.get(ADDRESS, 0);
            try {
                return parse(sd);
            } finally {
                localFree(sd);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static SecurityDescriptorInfo parse(MemorySegment sd) throws Throwable {
        try (var arena = Arena.ofConfined()) {
            var owner = arena.allocate(ADDRESS);
            var defaulted = arena.allocate(JAVA_INT);
            if ((int) Advapi32.GET_SD_OWNER.invokeExact(sd, owner, defaulted) == 0)
                throw new SecurityException("Could not read a security descriptor's owner.");
            var ownerPointer = owner.get(ADDRESS, 0);
            var ownerSid = isNull(ownerPointer) ? null : sidToString(ownerPointer);

            var present = arena.allocate(JAVA_INT);
            var dacl = arena.allocate(ADDRESS);
            if ((int) Advapi32.GET_SD_DACL.invokeExact(sd, present, dacl, defaulted) == 0)
                throw new SecurityException("Could not read a security descriptor's DACL.");
            var daclPointer = dacl.get(ADDRESS, 0);
            if (present.get(JAVA_INT, 0) == 0 || isNull(daclPointer))
                return new SecurityDescriptorInfo(ownerSid, true, List.of());

            // ACL header: AclRevision u8, Sbz1 u8, AclSize u16, AceCount u16 @4, Sbz2 u16.
            var aceCount = Short.toUnsignedInt(daclPointer.reinterpret(8).get(JAVA_SHORT, 4));
            var aces = new ArrayList<Ace>(aceCount);
            var acePointer = arena.allocate(ADDRESS);
            for (var i = 0; i < aceCount; i++) {
                if ((int) Advapi32.GET_ACE.invokeExact(daclPointer, i, acePointer) == 0)
                    throw new SecurityException("Could not read ACE " + i + " of a DACL.");

                // ACE_HEADER: AceType u8, AceFlags u8, AceSize u16; then, for the plain allow/deny
                // types and their callback forms, Mask u32 @4 and the SID @8.
                var ace = acePointer.get(ADDRESS, 0).reinterpret(8);
                var type = Byte.toUnsignedInt(ace.get(JAVA_BYTE, 0));
                var flags = Byte.toUnsignedInt(ace.get(JAVA_BYTE, 1));
                var size = Short.toUnsignedInt(ace.get(JAVA_SHORT, 2));
                var mask = ace.get(JAVA_INT, 4);
                var hasPlainSid = type == ACCESS_ALLOWED_ACE_TYPE || type == ACCESS_DENIED_ACE_TYPE
                        || type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE || type == ACCESS_DENIED_CALLBACK_ACE_TYPE;
                var sid = hasPlainSid ? sidToString(ace.reinterpret(size).asSlice(8)) : null;
                aces.add(new Ace(type, flags, mask, sid));
            }
            return new SecurityDescriptorInfo(ownerSid, false, List.copyOf(aces));
        }
    }

    private static String sidToString(MemorySegment sid) throws Throwable {
        try (var arena = Arena.ofConfined()) {
            var result = arena.allocate(ADDRESS);
            if ((int) Advapi32.CONVERT_SID_TO_STRING.invokeExact(sid, result) == 0)
                throw new SecurityException("Could not read a SID.");
            var text = result.get(ADDRESS, 0);
            try {
                return readWideString(text);
            } finally {
                localFree(text);
            }
        }
    }

    /** The account a SID maps to, as DOMAIN\name - or null if it maps to none here. */
    static String accountName(String sid) {
        try (var arena = Arena.ofConfined()) {
            var binary = arena.allocate(ADDRESS);
            if ((int) Advapi32.CONVERT_STRING_TO_SID.invokeExact(arena.allocateFrom(sid, UTF_16LE), binary) == 0)
                return null;

            var sidPointer = binary.get(ADDRESS, 0);
            try {
                var capacity = 256;
                var name = arena.allocate(JAVA_CHAR, capacity);
                var domain = arena.allocate(JAVA_CHAR, capacity);
                var nameLength = arena.allocateFrom(JAVA_INT, capacity);
                var domainLength = arena.allocateFrom(JAVA_INT, capacity);
                var use = arena.allocate(JAVA_INT);
                var ok = (int) Advapi32.LOOKUP_ACCOUNT_SID.invokeExact(MemorySegment.NULL, sidPointer, name, nameLength, domain, domainLength, use);
                if (ok == 0)
                    return null;

                var domainName = domain.getString(0, UTF_16LE);
                var accountName = name.getString(0, UTF_16LE);
                return domainName.isEmpty() ? accountName : domainName + "\\" + accountName;
            } finally {
                localFree(sidPointer);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // --- WinVerifyTrust ---------------------------------------------------------------------

    /**
     * What WinVerifyTrust reported for a file, and the signer's chain as WinVerifyTrust itself built
     * and validated it.
     *
     * @param status  0 when the signature is valid and trusted; otherwise the WinVerifyTrust HRESULT
     * @param leafDer the signing certificate (DER) when status is 0, else null
     * @param rootDer the root the chain ends at (DER) when status is 0, else null
     */
    record SignatureVerification(int status, byte[] leafDer, byte[] rootDer) {
    }

    // WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    private static final byte[] GENERIC_VERIFY_V2_TAIL = {(byte) 0x8C, (byte) 0xC2, 0x00, (byte) 0xC0, 0x4F, (byte) 0xC2, (byte) 0x95, (byte) 0xEE};
    private static final int UI_NONE = 2;                      // WTD_UI_NONE
    private static final int REVOKE_NONE = 0;                  // WTD_REVOKE_NONE
    private static final int CHOICE_FILE = 1;                  // WTD_CHOICE_FILE
    private static final int STATE_ACTION_VERIFY = 1;          // WTD_STATEACTION_VERIFY
    private static final int STATE_ACTION_CLOSE = 2;           // WTD_STATEACTION_CLOSE
    private static final int CACHE_ONLY_URL_RETRIEVAL = 0x1000; // WTD_CACHE_ONLY_URL_RETRIEVAL
    private static final int NO_SIGNER_CERT = 0x80096002;      // TRUST_E_NO_SIGNER_CERT

    // WINTRUST_FILE_INFO (x64): cbStruct u32 @0, pcwszFilePath @8, hFile @16, pgKnownSubject @24.
    private static final int FILE_INFO_SIZE = 32;
    // WINTRUST_DATA (x64): cbStruct @0, pPolicyCallbackData @8, pSIPClientData @16, dwUIChoice @24,
    // fdwRevocationChecks @28, dwUnionChoice @32, pFile @40, dwStateAction @48, hWVTStateData @56,
    // pwszURLReference @64, dwProvFlags @72, dwUIContext @76, pSignatureSettings @80.
    private static final int DATA_SIZE = 88;
    // CRYPT_PROVIDER_SGNR (x64): cbStruct @0 ... pChainContext @56, size 64.
    private static final int PROVIDER_SIGNER_SIZE = 64;

    /**
     * WinVerifyTrust with the generic Authenticode policy: checks that a file's embedded signature is
     * intact and chains to a trusted root (honouring a timestamp countersignature). Revocation isn't
     * checked and no network fetch is made, so loading the library never blocks on a CRL or OCSP
     * endpoint. The signer's chain is read from the verification state before it is released.
     */
    static SignatureVerification verifyEmbeddedSignature(String path) {
        try (var arena = Arena.ofConfined()) {
            var file = arena.allocate(FILE_INFO_SIZE, 8);
            file.set(JAVA_INT, 0, FILE_INFO_SIZE);
            file.set(ADDRESS, 8, arena.allocateFrom(path, UTF_16LE));

            var data = arena.allocate(DATA_SIZE, 8);
            data.set(JAVA_INT, 0, DATA_SIZE);
            data.set(JAVA_INT, 24, UI_NONE);
            data.set(JAVA_INT, 28, REVOKE_NONE);
            data.set(JAVA_INT, 32, CHOICE_FILE);
            data.set(ADDRESS, 40, file);
            data.set(JAVA_INT, 48, STATE_ACTION_VERIFY);
            data.set(JAVA_INT, 72, CACHE_ONLY_URL_RETRIEVAL);

            var action = guid(arena, 0x00AAC56B, (short) 0xCD44, (short) 0x11D0, GENERIC_VERIFY_V2_TAIL);
            var noInteractiveUser = MemorySegment.ofAddress(-1L); // INVALID_HANDLE_VALUE

            var status = (int) WinTrust.WIN_VERIFY_TRUST.invokeExact(noInteractiveUser, action, data);
            try {
                if (status == 0) {
                    var chain = readSignerChain(data.get(ADDRESS, 56));
                    if (chain != null)
                        return new SignatureVerification(0, chain[0], chain[1]);
                    status = NO_SIGNER_CERT;
                }
                return new SignatureVerification(status, null, null);
            } finally {
                // Release the state the verify call allocated, whatever it returned.
                data.set(JAVA_INT, 48, STATE_ACTION_CLOSE);
                var ignored = (int) WinTrust.WIN_VERIFY_TRUST.invokeExact(noInteractiveUser, action, data);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // The primary signer's leaf and root certificates, read from the verify call's state. Null if
    // any link is missing.
    private static byte[][] readSignerChain(MemorySegment stateData) throws Throwable {
        var provider = (MemorySegment) WinTrust.PROV_DATA_FROM_STATE_DATA.invokeExact(stateData);
        if (isNull(provider))
            return null;

        var signer = (MemorySegment) WinTrust.GET_PROV_SIGNER_FROM_CHAIN.invokeExact(provider, 0, 0, 0);
        if (isNull(signer))
            return null;
        signer = signer.reinterpret(PROVIDER_SIGNER_SIZE);
        if (Integer.toUnsignedLong(signer.get(JAVA_INT, 0)) < PROVIDER_SIGNER_SIZE)
            return null;

        // CERT_CHAIN_CONTEXT: cbSize @0, TrustStatus @4, cChain u32 @12, rgpChain @16.
        var chainContext = signer.get(ADDRESS, 56);
        if (isNull(chainContext))
            return null;
        chainContext = chainContext.reinterpret(24);
        var chainCount = chainContext.get(JAVA_INT, 12);
        var chains = chainContext.get(ADDRESS, 16);
        if (chainCount < 1 || isNull(chains))
            return null;
        chains = chains.reinterpret(chainCount * 8L);

        // The leaf is the first element of the first simple chain; the root, the last element of
        // the last one (cChain is 1 for an ordinary Authenticode chain).
        var leaf = certificate(chains.get(ADDRESS, 0), true);
        var root = certificate(chains.get(ADDRESS, (chainCount - 1) * 8L), false);
        return leaf == null || root == null ? null : new byte[][] {leaf, root};
    }

    // CERT_SIMPLE_CHAIN: cbSize @0, TrustStatus @4, cElement u32 @12, rgpElement @16.
    // CERT_CHAIN_ELEMENT: cbSize @0, pCertContext @8. CERT_CONTEXT: pbCertEncoded @8, cbCertEncoded u32 @16.
    private static byte[] certificate(MemorySegment simpleChain, boolean first) {
        if (isNull(simpleChain))
            return null;
        simpleChain = simpleChain.reinterpret(24);
        var elementCount = simpleChain.get(JAVA_INT, 12);
        var elements = simpleChain.get(ADDRESS, 16);
        if (elementCount < 1 || isNull(elements))
            return null;

        var element = elements.reinterpret(elementCount * 8L).get(ADDRESS, first ? 0 : (elementCount - 1) * 8L);
        if (isNull(element))
            return null;
        var context = element.reinterpret(16).get(ADDRESS, 8);
        if (isNull(context))
            return null;
        context = context.reinterpret(24);
        var encoded = context.get(ADDRESS, 8);
        var length = context.get(JAVA_INT, 16);
        if (isNull(encoded) || length <= 0)
            return null;
        return encoded.reinterpret(length).toArray(JAVA_BYTE);
    }

    private static MemorySegment guid(Arena arena, int data1, short data2, short data3, byte[] data4) {
        var guid = arena.allocate(16, 4);
        guid.set(JAVA_INT, 0, data1);
        guid.set(JAVA_SHORT, 4, data2);
        guid.set(JAVA_SHORT, 6, data3);
        MemorySegment.copy(data4, 0, guid, JAVA_BYTE, 8, 8);
        return guid;
    }
}
