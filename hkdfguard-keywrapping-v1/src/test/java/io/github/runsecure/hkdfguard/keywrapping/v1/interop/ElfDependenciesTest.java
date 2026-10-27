package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * DT_NEEDED and PT_INTERP parsing, against synthetic ELF images and, where installed, the real
 * library. Test names follow the .NET port's ElfDependenciesTests.
 */
class ElfDependenciesTest {
    private static final long LOAD_ADDRESS = 0x40_0000L;

    /** How a synthetic image departs from a well-formed one. */
    private record Options(boolean withDynamic, boolean withStringTable, Long stringTableAddressOverride, Long neededOffsetOverride,
            int stringTableSizeAdjustment, boolean withStringTableSize) {
        static final Options DEFAULT = new Options(true, true, null, null, 0, true);
    }

    private static byte[] elf(String... needed) {
        return elf(Options.DEFAULT, needed);
    }

    /**
     * A minimal 64-bit little-endian ELF image: one PT_LOAD mapping the whole file at
     * {@link #LOAD_ADDRESS}, one PT_DYNAMIC, and a string table holding the given names.
     */
    private static byte[] elf(Options options, String... needed) {
        final int header = 64;
        final int phdrs = 2 * 56;
        var strings = new ArrayList<Byte>();
        strings.add((byte) 0);
        var offsets = new ArrayList<Long>();
        for (var name : needed) {
            offsets.add(options.neededOffsetOverride() != null ? options.neededOffsetOverride() : (long) strings.size());
            for (var b : name.getBytes(StandardCharsets.UTF_8))
                strings.add(b);
            strings.add((byte) 0);
        }

        var dynamicEntries = new ArrayList<long[]>();
        for (var offset : offsets)
            dynamicEntries.add(new long[] {1, offset});
        var stringTableOffset = header + phdrs + (needed.length + 3) * 16;
        if (options.withStringTable()) {
            dynamicEntries.add(new long[] {5, options.stringTableAddressOverride() != null ? options.stringTableAddressOverride() : LOAD_ADDRESS + stringTableOffset});
            if (options.withStringTableSize())
                dynamicEntries.add(new long[] {10, strings.size() + options.stringTableSizeAdjustment()});
        }
        dynamicEntries.add(new long[] {0, 0});

        var image = new byte[stringTableOffset + strings.size()];
        var buffer = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        image[0] = 0x7F;
        image[1] = 'E';
        image[2] = 'L';
        image[3] = 'F';
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        buffer.putLong(32, header);       // e_phoff
        buffer.putShort(54, (short) 56);  // e_phentsize
        buffer.putShort(56, (short) 2);   // e_phnum

        var dynamicOffset = header + phdrs;
        programHeader(buffer, 0, 1, 0, LOAD_ADDRESS, image.length);
        programHeader(buffer, 1, options.withDynamic() ? 2 : 4, dynamicOffset, LOAD_ADDRESS + dynamicOffset, dynamicEntries.size() * 16L);
        for (var i = 0; i < dynamicEntries.size(); i++) {
            buffer.putLong(dynamicOffset + i * 16, dynamicEntries.get(i)[0]);
            buffer.putLong(dynamicOffset + i * 16 + 8, dynamicEntries.get(i)[1]);
        }

        for (var i = 0; i < strings.size(); i++)
            image[stringTableOffset + i] = strings.get(i);
        return image;
    }

    private static void programHeader(ByteBuffer image, int index, int type, long offset, long address, long size) {
        var at = 64 + index * 56;
        image.putInt(at, type);
        image.putLong(at + 8, offset);
        image.putLong(at + 16, address);
        image.putLong(at + 32, size);
    }

    private static List<String> parse(byte[] image) {
        return ElfDependencies.readNeeded("test.so",
                (offset, count) -> offset + count <= image.length ? Arrays.copyOfRange(image, (int) offset, (int) offset + count) : null);
    }

    @Test
    void readsEveryNeededName_InOrder() {
        assertEquals(List.of("libtss2-esys.so.0", "libc.so.6"), parse(elf("libtss2-esys.so.0", "libc.so.6")));
    }

    @Test
    void anObjectWithNoDependencies_HasNone() {
        assertEquals(List.of(), parse(elf()));
        assertEquals(List.of(), parse(elf(new Options(true, false, null, null, 0, true))));
        assertEquals(List.of(), parse(elf(new Options(false, true, null, null, 0, true), "ignored.so")));
    }

    static Stream<Arguments> malformedImages() {
        var notElf = elf("x.so");
        notElf[1] = 'X';
        var elf32 = elf("x.so");
        elf32[4] = 1;
        var bigEndian = elf("x.so");
        bigEndian[5] = 2;
        var noProgramHeaders = elf("x.so");
        ByteBuffer.wrap(noProgramHeaders).order(ByteOrder.LITTLE_ENDIAN).putShort(56, (short) 0);
        var hugeOffset = elf("x.so");
        ByteBuffer.wrap(hugeOffset).order(ByteOrder.LITTLE_ENDIAN).putLong(32, -1L); // ulong.MaxValue
        var hugeDynamic = elf("x.so");
        ByteBuffer.wrap(hugeDynamic).order(ByteOrder.LITTLE_ENDIAN).putLong(64 + 56 + 32, 2L << 20);
        var whole = elf("x.so");

        return Stream.of(
                Arguments.of("not an ELF file", notElf),
                Arguments.of("not a 64-bit little-endian", elf32),
                Arguments.of("not a 64-bit little-endian", bigEndian),
                Arguments.of("program header table is malformed", noProgramHeaders),
                Arguments.of("out of range", hugeOffset),
                Arguments.of("implausibly large", hugeDynamic),
                Arguments.of("runs past the end", Arrays.copyOf(whole, 40)),
                Arguments.of("runs past the end", Arrays.copyOf(whole, whole.length - 3)),
                Arguments.of("no string table", elf(new Options(true, false, null, null, 0, true), "x.so")),
                Arguments.of("no string table", elf(new Options(true, true, null, null, 0, false), "x.so")), // DT_STRTAB without DT_STRSZ
                Arguments.of("outside every loaded segment", elf(new Options(true, true, 0x10L, null, 0, true), "x.so")),
                Arguments.of("runs past its string table", elf(new Options(true, true, null, 4096L, 0, true), "x.so")),
                Arguments.of("runs past its string table", elf(new Options(true, true, null, null, -1, true), "x.so"))); // no terminating NUL
    }

    @ParameterizedTest
    @MethodSource("malformedImages")
    void aMalformedImage_IsRefused(String reason, byte[] image) {
        var ex = assertThrows(SecurityException.class, () -> parse(image));

        assertTrue(ex.getMessage().contains("test.so"));
        assertTrue(ex.getMessage().contains(reason), ex.getMessage());
    }

    /**
     * A minimal 64-bit little-endian ELF image with one PT_INTERP, whose segment is {@code size}
     * bytes holding {@code content}.
     */
    private static byte[] elfWithInterpreter(byte[] content, long size) {
        final int dataOffset = 64 + 56;
        var image = new byte[dataOffset + content.length];
        var buffer = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        image[0] = 0x7F;
        image[1] = 'E';
        image[2] = 'L';
        image[3] = 'F';
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        buffer.putLong(32, 64);           // e_phoff
        buffer.putShort(54, (short) 56);  // e_phentsize
        buffer.putShort(56, (short) 1);   // e_phnum
        programHeader(buffer, 0, 3, dataOffset, 0, size);
        System.arraycopy(content, 0, image, dataOffset, content.length);
        return image;
    }

    private static byte[] cString(String value) {
        return Arrays.copyOf(value.getBytes(StandardCharsets.UTF_8), value.length() + 1);
    }

    private static String parseInterpreter(byte[] image) {
        return ElfDependencies.readInterpreter("test",
                (offset, count) -> offset + count <= image.length ? Arrays.copyOfRange(image, (int) offset, (int) offset + count) : null);
    }

    @Test
    void readsTheInterpreterPath() {
        var path = cString("/lib64/ld-linux-x86-64.so.2");

        assertEquals("/lib64/ld-linux-x86-64.so.2", parseInterpreter(elfWithInterpreter(path, path.length)));
    }

    @Test
    void anObjectWithNoInterpreter_HasNone() {
        assertNull(parseInterpreter(elf("libc.so.6"))); // a shared object: PT_LOAD and PT_DYNAMIC only
    }

    static Stream<Arguments> malformedInterpreters() {
        var path = cString("/lib64/ld-linux-x86-64.so.2");
        var huge = new byte[ElfDependencies.MAX_INTERPRETER_BYTES + 1];
        Arrays.fill(huge, (byte) 'a');
        huge[huge.length - 1] = 0;
        var unterminated = "/lib64/ld-linux-x86-64.so.2".getBytes(StandardCharsets.UTF_8);

        return Stream.of(
                Arguments.of("empty or implausibly long", elfWithInterpreter(new byte[0], 0)),
                Arguments.of("empty or implausibly long", elfWithInterpreter(huge, huge.length)),
                Arguments.of("empty or implausibly long", elfWithInterpreter(path, -1L)), // ulong.MaxValue
                Arguments.of("not a NUL-terminated string", elfWithInterpreter(unterminated, unterminated.length)),
                Arguments.of("not a NUL-terminated string", elfWithInterpreter(new byte[] {0, 'x', 0}, 3)), // empty string
                Arguments.of("runs past the end", elfWithInterpreter(path, path.length + 8L)));
    }

    @ParameterizedTest
    @MethodSource("malformedInterpreters")
    void aMalformedInterpreterPath_IsRefused(String reason, byte[] image) {
        var ex = assertThrows(SecurityException.class, () -> parseInterpreter(image));

        assertTrue(ex.getMessage().contains(reason), ex.getMessage());
    }

    @Test
    void anOversizedProgramHeaderTable_IsRefusedBeforeItIsRead() {
        var image = elf("x.so");
        var buffer = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort(54, (short) 0xFFFF);
        buffer.putShort(56, (short) 4096);

        var ex = assertThrows(SecurityException.class, () -> parse(image));
        assertTrue(ex.getMessage().contains("program header table is implausibly large"), ex.getMessage());
    }

    @Test
    @EnabledOnOs(value = OS.LINUX, disabledReason = "Linux only.")
    void thisProcesssExecutable_NamesAnAbsoluteInterpreter() {
        var interpreter = ElfDependencies.readInterpreter("/proc/self/exe");

        assertNotNull(interpreter);
        assertTrue(interpreter.startsWith("/"), interpreter);
    }

    @Test
    void readsFromAFile() throws IOException {
        var path = Files.createTempFile("hkdfguard-elf-", ".so");
        try {
            Files.write(path, elf("libc.so.6"));
            assertEquals(List.of("libc.so.6"), ElfDependencies.readNeeded(path.toString()));

            Files.write(path, Arrays.copyOf(elf("libc.so.6"), 100));
            assertThrows(SecurityException.class, () -> ElfDependencies.readNeeded(path.toString()));
        } finally {
            Files.delete(path);
        }
    }

    @Test
    void theInstalledLibrary_NeedsTpm2TssAndLibc() {
        var installed = NativeTestEnvironment.assumeLinuxLibraryInstalled();
        var needed = ElfDependencies.readNeeded(installed);

        assertTrue(needed.contains("libtss2-esys.so.0"), needed.toString());
        assertTrue(needed.contains("libc.so.6"), needed.toString());
    }
}
