package io.github.runsecure.hkdfguard.keywrapping.v1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.NativeTestEnvironment;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Reading key files through the real native library's hkdfguard_open_file. Refusals of a file's
 * size, contents or location need no KEK, so they run wherever the Windows library is installed;
 * reading back a real wrapped key needs a provisioned service (see NativeTestEnvironment).
 */
class NativeKeyFileTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private Path directory;

    @BeforeEach
    void createDirectory() throws IOException {
        directory = NativeTestEnvironment.createTempDirectory("hkdfguard-keyfile-");
    }

    @AfterEach
    void deleteDirectory() throws IOException {
        try (var paths = Files.walk(directory)) {
            for (var path : paths.sorted(Comparator.reverseOrder()).toList())
                Files.deleteIfExists(path);
        }
    }

    // Any valid name: reading a file never touches a KEK.
    private static NativeHkdfKeyWrapperV1Impl reader() {
        return new NativeHkdfKeyWrapperV1Impl("hkdfguard.keyfile.reader");
    }

    private Path write(String name, byte[] contents) throws IOException {
        return Files.write(directory.resolve(name), contents);
    }

    private static Throwable readFailure(Path path) {
        var future = reader().readKeyFileAsync(path);
        assertTrue(future.isDone(), "native calls complete synchronously");
        return assertThrows(ExecutionException.class, future::get).getCause();
    }

    private static byte[] randomDek() {
        var dek = new byte[AbstractHkdfGuardKmsLibrary.DEK_LENGTH];
        RANDOM.nextBytes(dek);
        return dek;
    }

    private record WrappedFile(Path path, byte[] wrapped, byte[] dek) {
    }

    private WrappedFile wrapToFile(String service) throws Exception {
        var dek = randomDek();
        var buffer = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = new NativeHkdfKeyWrapperV1Impl(service).wrapAsync(dek.clone(), buffer).get();
        var wrapped = Arrays.copyOf(buffer, length);
        return new WrappedFile(write("wrapped-dek.bin", wrapped), wrapped, dek);
    }

    // --- The folder the key files are written to -------------------------------------------------

    @Test
    void theKeyFileFolder_IsInItsLongForm() {
        // hkdfguard_open_file refuses an 8.3 short name anywhere in a path, so every Windows test
        // here relies on NativeTestEnvironment.createTempDirectory expanding one (for example
        // C:\Users\RUNNER~1\... on GitHub-hosted runners).
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        for (var part : directory) {
            var name = part.toString();
            var tilde = name.indexOf('~');
            assertFalse(tilde >= 0 && tilde + 1 < name.length() && Character.isDigit(name.charAt(tilde + 1)),
                    directory + " still has the short name " + name);
        }
    }

    // --- Any platform's installed library --------------------------------------------------------

    @Test
    void theInstalledLibrary_AnswersOpenFile_WithADescribedRefusal() {
        // hkdfguard_open_file needs no KEK: a file that isn't there is refused with a status this
        // platform describes - which proves the binding reached it.
        NativeTestEnvironment.assumeLibraryInstalled();

        var failure = readFailure(directory.resolve("missing").resolve("dek.bin"));

        assertInstanceOf(IOException.class, failure);
        assertTrue(failure.getMessage().contains("refused by the native library with status"), failure.getMessage());
        assertFalse(failure.getMessage().contains("unknown status"), failure.getMessage());
    }

    // --- A real key file ------------------------------------------------------------------------

    @Test
    void aKeyFileTheWrapperWrote_ReadsBackStillWrapped_AndUnwrapsToItsDek() throws Exception {
        var service = NativeTestEnvironment.assumeService();
        var file = wrapToFile(service);
        var wrapper = new NativeHkdfKeyWrapperV1Impl(service);

        var read = wrapper.readKeyFileAsync(file.path()).get();

        assertArrayEquals(file.wrapped(), read);
        var recovered = new byte[file.dek().length];
        assertEquals(file.dek().length, wrapper.unwrapAsync(read, recovered).get());
        assertArrayEquals(file.dek(), recovered);
    }

    @Test
    void aKeyFileOfTheRightSizeWithAnUnknownVersion_IsMalformed() throws Exception {
        var file = wrapToFile(NativeTestEnvironment.assumeService());
        var wrapped = file.wrapped();
        wrapped[0] ^= (byte) 0xFF; // the version byte
        Files.write(file.path(), wrapped);

        var failure = assertInstanceOf(InvalidKeyFileException.class, readFailure(file.path()));

        assertTrue(failure.getMessage().contains("status -38"), failure.getMessage());
    }

    // --- Files the native library refuses, whatever the KEK --------------------------------------

    @Test
    void aMissingFile_IsNotFound() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        var path = directory.resolve("missing.bin");

        var failure = assertInstanceOf(NoSuchFileException.class, readFailure(path));

        assertEquals(path.toString(), failure.getFile());
        assertTrue(failure.getMessage().contains("status -32"), failure.getMessage());
    }

    @Test
    void aFileInAMissingFolder_IsNotFound() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        assertInstanceOf(NoSuchFileException.class, readFailure(directory.resolve("no-such-folder").resolve("dek.bin")));
    }

    static Stream<Arguments> plaintextKeys() {
        var dek = randomDek();
        var hex = HexFormat.of().withUpperCase().formatHex(dek);
        var base64 = Base64.getEncoder().encodeToString(dek);
        return Stream.of(
                Arguments.of("raw", dek),
                Arguments.of("hex", hex.getBytes(StandardCharsets.US_ASCII)),
                Arguments.of("lower-hex", HexFormat.of().formatHex(dek).getBytes(StandardCharsets.US_ASCII)),
                Arguments.of("base64", base64.getBytes(StandardCharsets.US_ASCII)),
                Arguments.of("base64-with-newline", (base64 + "\n").getBytes(StandardCharsets.US_ASCII)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("plaintextKeys")
    void aFileHoldingWhatLooksLikeAnUnwrappedKey_IsRefusedAsAKeyExposure(String form, byte[] contents) throws IOException {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        var path = write("plaintext-" + form + ".bin", contents);

        var failure = assertInstanceOf(InvalidKeyFileException.class, readFailure(path));

        assertTrue(failure.getMessage().contains("status -37"), failure.getMessage());
        assertTrue(failure.getMessage().contains("key exposure"), failure.getMessage());
    }

    @ParameterizedTest
    @CsvSource({"0, -35", "100, -35", "131, -35", "133, -36", "4096, -36"})
    void aFileOfTheWrongSize_IsRefused(int size, int status) throws IOException {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        var contents = new byte[size];
        if (size > 0)
            contents[0] = 0x7F; // never mistaken for text
        var path = write("size-" + size + ".bin", contents);

        var failure = assertInstanceOf(InvalidKeyFileException.class, readFailure(path));

        assertTrue(failure.getMessage().contains("status " + status), failure.getMessage());
    }

    @Test
    void aFolder_IsNotAKeyFile() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        assertInstanceOf(IOException.class, readFailure(directory));
    }

    @Test
    void aFileReachedThroughAJunction_IsUntrusted() throws Exception {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        var target = Files.createDirectory(directory.resolve("real"));
        Files.write(target.resolve("dek.bin"), new byte[132]);
        var junction = directory.resolve("junction");

        // mklink /J needs no elevation, unlike a symbolic link.
        var mklink = new ProcessBuilder("cmd.exe", "/c", "mklink", "/J", junction.toString(), target.toString())
                .redirectErrorStream(true)
                .start();
        var output = new String(mklink.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(mklink.waitFor(30, TimeUnit.SECONDS), "mklink timed out");
        assertEquals(0, mklink.exitValue(), output);

        try {
            var failure = assertInstanceOf(AccessDeniedException.class, readFailure(junction.resolve("dek.bin")));

            assertTrue(failure.getMessage().contains("status -39"), failure.getMessage());
        } finally {
            // Removes the junction itself, not what it points at - before the folder is walked.
            Files.delete(junction);
        }
    }
}
