package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads the DT_NEEDED entries - the shared libraries an ELF object asks the dynamic linker to load
 * - and the PT_INTERP path - the dynamic linker an executable names - from a 64-bit little-endian
 * ELF file (x86-64 and arm64 Linux). Only the ELF header, the program headers, the interpreter path,
 * the dynamic segment and its string table are read, each bounded. Anything malformed is refused:
 * the caller is deciding whether to trust what the file pulled into the process. A port of the .NET
 * port's ElfDependencies.
 */
final class ElfDependencies {
    private static final int HEADER_SIZE = 64;
    private static final int PROGRAM_HEADER_SIZE = 56;
    private static final int DYNAMIC_ENTRY_SIZE = 16;
    private static final int MAX_PROGRAM_HEADERS = 4096;
    private static final int MAX_SEGMENT_BYTES = 1 << 20;

    private static final int PT_LOAD = 1;
    private static final int PT_DYNAMIC = 2;
    private static final int PT_INTERP = 3;

    /** Bounds PT_INTERP, a path: PATH_MAX. */
    static final int MAX_INTERPRETER_BYTES = 4096;

    private static final long DT_NULL = 0;
    private static final long DT_NEEDED = 1;
    private static final long DT_STRTAB = 5;
    private static final long DT_STRSZ = 10;

    /** Reads exactly {@code count} bytes at {@code offset}, or returns null if the file is shorter. */
    @FunctionalInterface
    interface RangeReader {
        byte[] read(long offset, int count);
    }

    private record Load(long virtualAddress, long fileSize, long offset) {
    }

    /** The program header table, little-endian, and the size and number of its entries. */
    private record ProgramHeaders(ByteBuffer table, int entrySize, int count) {
    }

    /** Parses through a {@link RangeReader} over an open file. */
    @FunctionalInterface
    private interface Parser<T> {
        T parse(RangeReader read);
    }

    private ElfDependencies() {
    }

    /**
     * The DT_NEEDED names of the ELF file at {@code path}, in file order.
     *
     * @throws SecurityException    the file is not a well-formed 64-bit little-endian ELF object
     * @throws UncheckedIOException the file could not be read
     */
    static List<String> readNeeded(String path) {
        return parseFile(path, read -> readNeeded(path, read));
    }

    /**
     * The PT_INTERP path of the ELF file at {@code path} - for an executable, the dynamic linker the
     * kernel started it with - or null if it has none.
     *
     * @throws SecurityException    the file is not a well-formed 64-bit little-endian ELF object
     * @throws UncheckedIOException the file could not be read
     */
    static String readInterpreter(String path) {
        return parseFile(path, read -> readInterpreter(path, read));
    }

    private static <T> T parseFile(String path, Parser<T> parser) {
        try (var file = FileChannel.open(Path.of(path), StandardOpenOption.READ)) {
            return parser.parse((offset, count) -> {
                try {
                    var buffer = ByteBuffer.allocate(count);
                    while (buffer.hasRemaining()) {
                        if (file.read(buffer, offset + buffer.position()) <= 0)
                            break;
                    }
                    return buffer.hasRemaining() ? null : buffer.array();
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * @param path the file's name, for messages
     * @param read reads exactly count bytes at offset, or returns null if the file is shorter
     */
    static List<String> readNeeded(String path, RangeReader read) {
        var headers = readProgramHeaders(path, read);
        var programHeaders = headers.table();
        var programHeaderSize = headers.entrySize();
        var programHeaderCount = headers.count();
        var loads = new ArrayList<Load>();
        long dynamicOffset = -1;
        var dynamicSize = 0;
        for (var i = 0; i < programHeaderCount; i++) {
            var at = i * programHeaderSize;
            var type = programHeaders.getInt(at);
            var offset = toOffset(path, programHeaders.getLong(at + 8));
            var virtualAddress = programHeaders.getLong(at + 16);
            var fileSize = programHeaders.getLong(at + 32);

            if (type == PT_LOAD)
                loads.add(new Load(virtualAddress, fileSize, offset));
            else if (type == PT_DYNAMIC) {
                dynamicOffset = offset;
                dynamicSize = toSize(path, fileSize, "dynamic segment");
            }
        }

        if (dynamicOffset < 0)
            return List.of();

        var neededOffsets = new ArrayList<Long>();
        Long stringTableAddress = null;
        Long stringTableSize = null;
        var entriesBytes = read(path, read, dynamicOffset, dynamicSize - dynamicSize % DYNAMIC_ENTRY_SIZE, "dynamic segment");
        var entries = littleEndian(entriesBytes);
        for (var at = 0; at + DYNAMIC_ENTRY_SIZE <= entriesBytes.length; at += DYNAMIC_ENTRY_SIZE) {
            var tag = entries.getLong(at);
            var value = entries.getLong(at + 8);
            if (tag == DT_NULL)
                break;
            if (tag == DT_NEEDED)
                neededOffsets.add(value);
            else if (tag == DT_STRTAB)
                stringTableAddress = value;
            else if (tag == DT_STRSZ)
                stringTableSize = value;
        }

        if (neededOffsets.isEmpty())
            return List.of();
        if (stringTableAddress == null || stringTableSize == null)
            throw malformed(path, "it names dependencies but has no string table");

        // DT_STRTAB is a virtual address; the PT_LOAD segment containing it maps it to the file.
        // Addresses and sizes are unsigned 64-bit values.
        long address = stringTableAddress;
        var containing = loads.stream()
                .filter(l -> Long.compareUnsigned(address, l.virtualAddress()) >= 0 && Long.compareUnsigned(address - l.virtualAddress(), l.fileSize()) < 0)
                .findFirst()
                .orElseThrow(() -> malformed(path, "its string table lies outside every loaded segment"));

        long stringsOffset;
        try {
            stringsOffset = Math.addExact(containing.offset(), toOffset(path, address - containing.virtualAddress()));
        } catch (ArithmeticException e) {
            throw malformed(path, "a file offset is out of range");
        }

        var strings = read(path, read, stringsOffset, toSize(path, stringTableSize, "string table"), "string table");
        var names = new ArrayList<String>(neededOffsets.size());
        for (long offset : neededOffsets) {
            var end = -1;
            if (Long.compareUnsigned(offset, strings.length) < 0) {
                for (var i = (int) offset; i < strings.length; i++) {
                    if (strings[i] == 0) {
                        end = i;
                        break;
                    }
                }
            }
            if (end < 0)
                throw malformed(path, "a dependency name runs past its string table");

            names.add(new String(strings, (int) offset, end - (int) offset, StandardCharsets.UTF_8));
        }

        return List.copyOf(names);
    }

    /**
     * @param path the file's name, for messages
     * @param read reads exactly count bytes at offset, or returns null if the file is shorter
     * @return the PT_INTERP path, or null if there is none
     */
    static String readInterpreter(String path, RangeReader read) {
        var headers = readProgramHeaders(path, read);
        var programHeaders = headers.table();
        for (var i = 0; i < headers.count(); i++) {
            var at = i * headers.entrySize();
            if (programHeaders.getInt(at) != PT_INTERP)
                continue;

            var offset = toOffset(path, programHeaders.getLong(at + 8));
            var fileSize = programHeaders.getLong(at + 32);
            if (fileSize <= 0 || fileSize > MAX_INTERPRETER_BYTES) // unsigned: a negative long is huge
                throw malformed(path, "its interpreter path is empty or implausibly long");

            var raw = read(path, read, offset, (int) fileSize, "interpreter path");
            var end = 0;
            while (end < raw.length && raw[end] != 0)
                end++;
            if (end == 0 || end == raw.length)
                throw malformed(path, "its interpreter path is not a NUL-terminated string");

            return new String(raw, 0, end, StandardCharsets.UTF_8);
        }

        return null;
    }

    // Validates the ELF header and reads the program header table.
    private static ProgramHeaders readProgramHeaders(String path, RangeReader read) {
        var header = read(path, read, 0, HEADER_SIZE, "ELF header");
        if (header[0] != 0x7F || header[1] != 'E' || header[2] != 'L' || header[3] != 'F')
            throw malformed(path, "it is not an ELF file");
        if (header[4] != 2 || header[5] != 1)
            throw malformed(path, "it is not a 64-bit little-endian ELF file");

        var h = littleEndian(header);
        var programHeaderOffset = toOffset(path, h.getLong(32));
        var programHeaderSize = Short.toUnsignedInt(h.getShort(54));
        var programHeaderCount = Short.toUnsignedInt(h.getShort(56));
        if (programHeaderSize < PROGRAM_HEADER_SIZE || programHeaderCount == 0 || programHeaderCount > MAX_PROGRAM_HEADERS)
            throw malformed(path, "its program header table is malformed");

        // Both fields are 16-bit, so their product can reach 256 MB; bound the table like every
        // other region read, before anything is allocated for it.
        var tableBytes = toSize(path, (long) programHeaderSize * programHeaderCount, "program header table");
        return new ProgramHeaders(littleEndian(read(path, read, programHeaderOffset, tableBytes, "program headers")), programHeaderSize, programHeaderCount);
    }

    private static ByteBuffer littleEndian(byte[] bytes) {
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static byte[] read(String path, RangeReader read, long offset, int count, String what) {
        var bytes = read.read(offset, count);
        if (bytes == null || bytes.length != count)
            throw malformed(path, "its " + what + " runs past the end of the file");
        return bytes;
    }

    // An unsigned 64-bit offset, which must fit in a (signed) long.
    private static long toOffset(String path, long value) {
        if (value < 0)
            throw malformed(path, "a file offset is out of range");
        return value;
    }

    private static int toSize(String path, long value, String what) {
        if (Long.compareUnsigned(value, MAX_SEGMENT_BYTES) > 0)
            throw malformed(path, "its " + what + " is implausibly large");
        return (int) value;
    }

    private static SecurityException malformed(String path, String reason) {
        return new SecurityException("'" + path + "' is not a well-formed ELF shared object: " + reason + ".");
    }
}
