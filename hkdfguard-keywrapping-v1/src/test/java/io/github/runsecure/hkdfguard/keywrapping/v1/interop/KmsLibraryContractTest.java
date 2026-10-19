package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class KmsLibraryContractTest {
    /** Every status code, exactly as every platform's hkdfguard.h defines it: {constant, header value}. */
    static Stream<Arguments> sharedStatusCodes() {
        return Stream.of(
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT, -1),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL, -2),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_PROVIDER_UNAVAILABLE, -3),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_PROVIDER_ERROR, -4),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_CRYPTO_ERROR, -5),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_INTERNAL_ERROR, -6),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, -8),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_POLICY_INVALID, -9),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED, -10),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_AUTH_FAILED, -11),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_UNSUPPORTED, -12),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH, -16),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND, -17),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED, -18),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_KEK_INVALID, -19),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_PROCESS_HARDENING_FAILED, -20),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND, -32),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_ACCESS_DENIED, -33),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_IO, -34),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_SHORT, -35),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_LONG, -36),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY, -37),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_MALFORMED, -38),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED, -39),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_WIN_GROUP_INVALID, -64),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_MAC_ACCESS_CONTROL_CREATION_FAILED, -96),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_MAC_KEY_GENERATION_FAILED, -97),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_MAC_KEYCHAIN_WRITE_FAILED, -98),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_MAC_KEK_VERIFICATION_FAILED, -99),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_MAC_KEYCHAIN_READ_FAILED, -100));
    }

    private static int[] definedCodes() {
        return sharedStatusCodes().mapToInt(arguments -> (int) arguments.get()[1]).toArray();
    }

    private static AbstractHkdfGuardKmsLibrary libraryFor(String platform) {
        return switch (platform) {
            case "Windows" -> new WindowsHkdfGuardKmsLibrary();
            case "Linux" -> new LinuxHkdfGuardKmsLibrary();
            default -> new MacOsHkdfGuardKmsLibrary();
        };
    }

    @Test
    void sharedConstants_MatchTheNativeHeaders() {
        assertEquals(32, AbstractHkdfGuardKmsLibrary.DEK_LENGTH);
        assertEquals(0, AbstractHkdfGuardKmsLibrary.OK);
    }

    @ParameterizedTest
    @MethodSource("sharedStatusCodes")
    void theStatusCodes_MatchTheNativeHeader(int constant, int expected) {
        assertEquals(expected, constant);
    }

    @ParameterizedTest
    @ValueSource(strings = {"Windows", "Linux", "macOS"})
    void everyPlatform_DescribesEveryDefinedStatus_AndNothingElse(String platform) {
        var library = libraryFor(platform);

        for (var status : definedCodes()) {
            var description = library.describeStatus(status);
            assertFalse(description == null || description.isEmpty(), platform + ": no description for " + status);
        }

        // Reserved and unassigned codes, and anything positive or zero, have no meaning to describe.
        var defined = definedCodes();
        IntStream.rangeClosed(-130, 1)
                .filter(status -> IntStream.of(defined).noneMatch(code -> code == status))
                .forEach(status -> assertNull(library.describeStatus(status), platform + ": described reserved status " + status));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Windows", "Linux", "macOS"})
    void everyPlatform_SaysHowToProvisionAMissingKek(String platform) {
        assertTrue(libraryFor(platform).describeStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND).contains("provision"));
    }

    @Test
    void windows_SaysWhichGroupGrantsAccessToAKek() {
        var description = new WindowsHkdfGuardKmsLibrary().describeStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED);

        assertTrue(description.contains("not authorized"));
        assertTrue(description.contains("HkdfGuardUsers"));
        assertTrue(description.contains("KeyUseGroups"));
    }

    @Test
    void windows_NamesTheMachinePolicyKey() {
        assertTrue(new WindowsHkdfGuardKmsLibrary().describeStatus(AbstractHkdfGuardKmsLibrary.ERR_POLICY_INVALID)
                .contains("HKLM\\Software\\Policies\\HkdfGuard"));
    }

    @Test
    void windows_NamesTheCurrentCommandLineTool() {
        var description = new WindowsHkdfGuardKmsLibrary().describeStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND);

        assertTrue(description.contains("hkdfguard provision"));
        assertFalse(description.contains("v1-initialize"));
    }

    @Test
    void linux_NamesThePolicyFile_AndTheCurrentCommandLineTool() {
        var library = new LinuxHkdfGuardKmsLibrary();

        assertTrue(library.describeStatus(AbstractHkdfGuardKmsLibrary.ERR_POLICY_INVALID).contains("/etc/hkdfguard/policy.toml"));
        assertTrue(library.describeStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH).contains("different KEK"));
        assertTrue(library.describeStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND).contains("hkdfguard provision"));
    }

    @Test
    void macOs_NamesTheKeychain() {
        var library = new MacOsHkdfGuardKmsLibrary();

        assertTrue(library.describeStatus(AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED).contains("keychain"));
        assertTrue(library.describeStatus(AbstractHkdfGuardKmsLibrary.ERR_PROVIDER_UNAVAILABLE).contains("Secure Enclave"));
    }

    @Test
    void aPlatformFallsBackToTheSharedDescriptions() {
        var shared = new StubLibrary();

        for (var platform : new String[] {"Windows", "Linux", "macOS"})
            assertEquals(shared.describeStatus(AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED),
                    libraryFor(platform).describeStatus(AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED));
    }

    @Test
    void aPlaintextKeyFile_IsDescribedAsAKeyExposure() {
        assertTrue(new StubLibrary().describeStatus(AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY).contains("key exposure"));
    }

    // --- openFile: the interop returns the file's bytes, or throws ---------------------------------

    /** A library whose hkdfguard_open_file is scripted, recording every call. */
    private static final class StubLibrary extends AbstractHkdfGuardKmsLibrary {
        int openFileStatus = OK;
        byte[] payload = new byte[132];
        String lastPath;
        int lastCapacity;
        int openFileCallCount;

        @Override
        public KmsResult wrapDek(String service, byte[] dek, byte[] destination) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KmsResult unwrapDek(String service, byte[] wrapped, byte[] destination) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KmsResult generateAndWrapDek(String service, byte[] destination) {
            throw new UnsupportedOperationException();
        }

        @Override
        protected KmsResult openFileRaw(String path, byte[] destination) {
            openFileCallCount++;
            lastPath = path;
            lastCapacity = destination.length;
            if (openFileStatus != OK)
                return new KmsResult(openFileStatus, 0);

            System.arraycopy(payload, 0, destination, 0, payload.length);
            return new KmsResult(OK, payload.length);
        }
    }

    @Test
    void openFile_ReturnsExactlyTheBytesTheNativeLibraryRead() throws IOException {
        var library = new StubLibrary();
        library.payload = new byte[132];
        for (var i = 0; i < library.payload.length; i++)
            library.payload[i] = (byte) i;

        var bytes = library.openFile("C:\\keys\\dek.bin");

        assertArrayEquals(library.payload, bytes);
        assertEquals("C:\\keys\\dek.bin", library.lastPath);
        assertEquals(1, library.openFileCallCount);
    }

    @Test
    void openFile_PassesABufferLargeEnoughForEveryPlatformsWrappedDek() throws IOException {
        var library = new StubLibrary();
        library.payload = new byte[WrappedKeyLimits.MAX_BYTES];

        assertEquals(WrappedKeyLimits.MAX_BYTES, library.openFile("dek.bin").length);
        assertEquals(WrappedKeyLimits.MAX_BYTES, library.lastCapacity);
    }

    static Stream<Arguments> openFileFailures() {
        return Stream.of(
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND, NoSuchFileException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_ACCESS_DENIED, AccessDeniedException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED, AccessDeniedException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_SHORT, InvalidKeyFileException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_LONG, InvalidKeyFileException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY, InvalidKeyFileException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_MALFORMED, InvalidKeyFileException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_FILE_IO, IOException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT, IllegalArgumentException.class),
                Arguments.of(AbstractHkdfGuardKmsLibrary.ERR_INTERNAL_ERROR, IOException.class));
    }

    @ParameterizedTest
    @MethodSource("openFileFailures")
    void openFile_TurnsEachRefusalIntoTheMatchingException(int status, Class<? extends Exception> expected) {
        var library = new StubLibrary();
        library.openFileStatus = status;

        var thrown = assertThrows(Exception.class, () -> library.openFile("C:\\keys\\dek.bin"));

        // Exactly the expected type: a plain IOException must not be a more specific one, and vice versa.
        assertEquals(expected, thrown.getClass());
        var reason = thrown instanceof FileSystemException fileSystem ? fileSystem.getReason() : thrown.getMessage();
        assertEquals("Key file 'C:\\keys\\dek.bin' was refused by the native library with status " + status
                + " (" + library.describeStatus(status) + ").", reason);
        assertTrue(thrown.getMessage().contains("C:\\keys\\dek.bin"));
        assertTrue(thrown.getMessage().contains("status " + status));
    }

    @Test
    void openFile_NamesTheMissingFile() {
        var library = new StubLibrary();
        library.openFileStatus = AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND;

        var thrown = assertThrows(NoSuchFileException.class, () -> library.openFile("missing.bin"));

        assertEquals("missing.bin", thrown.getFile());
    }

    @Test
    void openFile_NamesAnUntrustedFile() {
        var library = new StubLibrary();
        library.openFileStatus = AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED;

        var thrown = assertThrows(AccessDeniedException.class, () -> library.openFile("junction\\dek.bin"));

        assertEquals("junction\\dek.bin", thrown.getFile());
        assertTrue(thrown.getMessage().contains("not trusted"));
    }

    @Test
    void openFile_SaysWhenAStatusIsUnknown() {
        var library = new StubLibrary();
        library.openFileStatus = -63;

        var thrown = assertThrows(IOException.class, () -> library.openFile("dek.bin"));

        assertEquals(IOException.class, thrown.getClass());
        assertTrue(thrown.getMessage().endsWith("with status -63 (unknown status)."));
    }

    @Test
    void openFile_RefusesANullPath_BeforeReachingTheNativeLibrary() {
        var library = new StubLibrary();

        assertThrows(NullPointerException.class, () -> library.openFile(null));
        assertEquals(0, library.openFileCallCount);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "dek.bin\0.txt"})
    void openFile_RefusesAnEmptyPathOrOneWithANul_BeforeReachingTheNativeLibrary(String path) {
        var library = new StubLibrary();

        assertInstanceOf(IllegalArgumentException.class, assertThrows(RuntimeException.class, () -> library.openFile(path)));
        assertEquals(0, library.openFileCallCount);
    }
}
