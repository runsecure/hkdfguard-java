package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static io.github.runsecure.hkdfguard.platform.NativeCalls.isNull;
import static io.github.runsecure.hkdfguard.platform.NativeCalls.readWideString;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;
import static java.nio.charset.StandardCharsets.UTF_16LE;

import io.github.runsecure.hkdfguard.platform.NativeCalls;
import io.github.runsecure.hkdfguard.platform.windows.WindowsSecurity;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * The Win32 calls the Windows loader's checks rely on, bound through the FFM API: known-folder
 * lookup, version resources, WinVerifyTrust, and LoadLibraryExW / GetProcAddress. File attributes,
 * security descriptors and SIDs are hkdfguard-platform's WindowsSecurity, shared with the key-file
 * checks. kernel32 is a KnownDLL, always mapped from System32. Every other system library here
 * (shell32, ole32, wintrust, version) is loaded by its absolute System32 path
 * through {@link SymbolLookup#libraryLookup(Path, Arena)}, a plain LoadLibrary of that path: the
 * library itself can't be planted in the application directory or on PATH, but the imports it
 * pulls in that aren't KnownDLLs (wintrust.dll's crypt32.dll and msasn1.dll, for example) are
 * found by the default DLL search order, which starts at the application directory - the JDK's
 * bin folder. The HkdfGuard DLL is loaded differently ({@link #loadLibrary}): LoadLibraryExW with
 * LOAD_LIBRARY_SEARCH_SYSTEM32, so its dependencies come from System32 only. Each library is bound
 * only on first use, so this class is inert off Windows. 64-bit Windows only - the only Windows
 * the JDK still supports.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class Win32 {
    private static final int LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;
    private static final int KF_FLAG_DONT_VERIFY = 0x4000;

    private static final Linker.Option CAPTURE_LAST_ERROR = Linker.Option.captureCallState("GetLastError");
    private static final MemoryLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
    private static final VarHandle LAST_ERROR = CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));

    private Win32() {
    }

    // --- Binding ---------------------------------------------------------------------------

    private static MethodHandle bind(SymbolLookup library, String name, FunctionDescriptor descriptor, Linker.Option... options) {
        return NativeCalls.bind(library, "Windows", name, descriptor, options);
    }

    private static SymbolLookup system32(String fileName) {
        return SymbolLookup.libraryLookup(Path.of(WindowsSecurity.systemDirectory(), fileName), Arena.global());
    }

    private static final class Kernel32 {
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
        static final MethodHandle LOAD_LIBRARY_EX = bind(LIBRARY, "LoadLibraryExW", FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_INT), CAPTURE_LAST_ERROR);
        static final MethodHandle GET_PROC_ADDRESS = bind(LIBRARY, "GetProcAddress", FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle GET_MODULE_FILE_NAME = bind(LIBRARY, "GetModuleFileNameW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT), CAPTURE_LAST_ERROR);
        static final MethodHandle FREE_LIBRARY = bind(LIBRARY, "FreeLibrary", FunctionDescriptor.of(JAVA_INT, ADDRESS));
    }

    private static final class Shell32 {
        static final SymbolLookup LIBRARY = system32("shell32.dll");
        static final MethodHandle SH_GET_KNOWN_FOLDER_PATH = bind(LIBRARY, "SHGetKnownFolderPath", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS));
    }

    private static final class Ole32 {
        static final SymbolLookup LIBRARY = system32("ole32.dll");
        static final MethodHandle CO_TASK_MEM_FREE = bind(LIBRARY, "CoTaskMemFree", FunctionDescriptor.ofVoid(ADDRESS));
    }

    private static final class WinTrust {
        static final SymbolLookup LIBRARY = system32("wintrust.dll");
        static final MethodHandle WIN_VERIFY_TRUST = bind(LIBRARY, "WinVerifyTrust", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle PROV_DATA_FROM_STATE_DATA = bind(LIBRARY, "WTHelperProvDataFromStateData", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle GET_PROV_SIGNER_FROM_CHAIN = bind(LIBRARY, "WTHelperGetProvSignerFromChain",
                FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT));
    }

    private static final class Version {
        static final SymbolLookup LIBRARY = system32("version.dll");
        static final MethodHandle GET_FILE_VERSION_INFO_SIZE = bind(LIBRARY, "GetFileVersionInfoSizeW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle GET_FILE_VERSION_INFO = bind(LIBRARY, "GetFileVersionInfoW", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS));
        static final MethodHandle VER_QUERY_VALUE = bind(LIBRARY, "VerQueryValueW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    }

    /**
     * The file version {major, minor, patch} from a file's version resource, read through
     * version.dll from System32; null if it has none or it can't be read.
     */
    static int[] fileVersion(String path) {
        try (var arena = Arena.ofConfined()) {
            var name = arena.allocateFrom(path, UTF_16LE);
            var size = (int) Version.GET_FILE_VERSION_INFO_SIZE.invokeExact(name, MemorySegment.NULL);
            if (size <= 0)
                return null;
            var block = arena.allocate(size);
            if ((int) Version.GET_FILE_VERSION_INFO.invokeExact(name, 0, size, block) == 0)
                return null;
            var info = arena.allocate(ADDRESS);
            var length = arena.allocate(JAVA_INT);
            if ((int) Version.VER_QUERY_VALUE.invokeExact(block, arena.allocateFrom("\\", UTF_16LE), info, length) == 0)
                return null;
            var fixedInfo = info.get(ADDRESS, 0);
            if (isNull(fixedInfo) || length.get(JAVA_INT, 0) < 52)
                return null;
            // VS_FIXEDFILEINFO: signature, struct version, file version MS, file version LS, ...
            fixedInfo = fixedInfo.reinterpret(52);
            if (fixedInfo.get(JAVA_INT, 0) != 0xFEEF04BD)
                return null;
            var ms = fixedInfo.get(JAVA_INT, 8);
            var ls = fixedInfo.get(JAVA_INT, 12);
            return new int[] {ms >>> 16, ms & 0xFFFF, ls >>> 16};
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static RuntimeException rethrow(Throwable t) {
        return NativeCalls.rethrow(t, "A Win32 call failed.");
    }

    // --- Paths and loading ------------------------------------------------------------------

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

    /**
     * GetModuleFileNameW: the file Windows mapped a loaded module from.
     *
     * @throws IllegalStateException it can't be read
     */
    static String moduleFileName(MemorySegment module) {
        try (var arena = Arena.ofConfined()) {
            var capacity = 32768; // the longest path Windows supports, plus its terminator
            var buffer = arena.allocate(JAVA_CHAR, capacity);
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var length = (int) Kernel32.GET_MODULE_FILE_NAME.invokeExact(capture, module, buffer, capacity);
            if (length <= 0 || length >= capacity)
                throw new IllegalStateException("GetModuleFileNameW failed with error " + (int) LAST_ERROR.get(capture, 0L) + ".");
            return buffer.getString(0, UTF_16LE);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** FreeLibrary: releases a reference {@link #loadLibrary(String)} took. */
    static void freeLibrary(MemorySegment module) {
        try {
            var ignored = (int) Kernel32.FREE_LIBRARY.invokeExact(module);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * LoadLibraryExW of an absolute path, with the library's own dependencies resolved from
     * System32 only - never the application directory or PATH. Never unloaded once verified.
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
        @Override
        public boolean equals(Object other) {
            return other instanceof SignatureVerification that && status == that.status && Arrays.equals(leafDer, that.leafDer)
                    && Arrays.equals(rootDer, that.rootDer);
        }

        @Override
        public int hashCode() {
            return Objects.hash(status, Arrays.hashCode(leafDer), Arrays.hashCode(rootDer));
        }

        @Override
        public String toString() {
            return String.format("SignatureVerification[status=0x%08X, leafDer=%s, rootDer=%s]", status,
                    leafDer == null ? "none" : leafDer.length + " bytes", rootDer == null ? "none" : rootDer.length + " bytes");
        }
    }

    // WINTRUST_ACTION_GENERIC_VERIFY_V2 {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    private static final byte[] GENERIC_VERIFY_V2_TAIL = {(byte) 0x8C, (byte) 0xC2, 0x00, (byte) 0xC0, 0x4F, (byte) 0xC2, (byte) 0x95, (byte) 0xEE};
    private static final int UI_NONE = 2;                      // WTD_UI_NONE
    private static final int REVOKE_NONE = 0;                  // WTD_REVOKE_NONE
    private static final int CHOICE_FILE = 1;                  // WTD_CHOICE_FILE
    private static final int STATE_ACTION_VERIFY = 1;          // WTD_STATEACTION_VERIFY
    private static final int STATE_ACTION_CLOSE = 2;           // WTD_STATEACTION_CLOSE
    private static final int CACHE_ONLY_URL_RETRIEVAL = 0x1000; // WTD_CACHE_ONLY_URL_RETRIEVAL
    private static final int REVOKE_WHOLE_CHAIN = 1;            // WTD_REVOKE_WHOLECHAIN
    private static final int STATE_ACTION_IGNORE = 0;           // WTD_STATEACTION_IGNORE
    private static final int REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x80; // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
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
     * intact and chains to a trusted root (honouring a timestamp countersignature), with no
     * revocation check and no network fetch. The signer's chain is read from the verification state
     * before it is released. Revocation is a second, separate pass: {@link #checkRevocation}.
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

    /**
     * Verifies the signature again, this time checking every certificate in the chain below the root
     * for revocation, fetching revocation information over the network if it isn't cached. No state
     * is kept, so there is nothing to release. Not lifetime signing: a timestamped signature stays
     * valid after its short-lived certificate expires.
     *
     * @param path the signed file, already accepted by {@link #verifyEmbeddedSignature}
     * @return the WinVerifyTrust HRESULT; see {@link WindowsRevocationPolicy#refuses}
     */
    static int checkRevocation(String path) {
        try (var arena = Arena.ofConfined()) {
            var file = arena.allocate(FILE_INFO_SIZE, 8);
            file.set(JAVA_INT, 0, FILE_INFO_SIZE);
            file.set(ADDRESS, 8, arena.allocateFrom(path, UTF_16LE));

            var data = arena.allocate(DATA_SIZE, 8);
            data.set(JAVA_INT, 0, DATA_SIZE);
            data.set(JAVA_INT, 24, UI_NONE);
            data.set(JAVA_INT, 28, REVOKE_WHOLE_CHAIN);
            data.set(JAVA_INT, 32, CHOICE_FILE);
            data.set(ADDRESS, 40, file);
            data.set(JAVA_INT, 48, STATE_ACTION_IGNORE);
            data.set(JAVA_INT, 72, REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT);

            var action = guid(arena, 0x00AAC56B, (short) 0xCD44, (short) 0x11D0, GENERIC_VERIFY_V2_TAIL);
            var noInteractiveUser = MemorySegment.ofAddress(-1L); // INVALID_HANDLE_VALUE
            return (int) WinTrust.WIN_VERIFY_TRUST.invokeExact(noInteractiveUser, action, data);
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
