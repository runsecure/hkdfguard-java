package io.github.runsecure.hkdfguard.pipeline.contract;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads a tar archive back for a test - ustar headers and the PAX extended headers ('x') before
 * them, as a writer of PAX archives writes them - checking every header's checksum and that the
 * archive ends with two zero blocks. Only as much of the format as the pipeline writes; the real
 * tars' reading of it is tested by running them.
 */
public final class TarEntries {
    /** One entry: its type flag, its name (the extended header's path, if any), mode, times and data. */
    public record Entry(char type, String name, int mode, long mtime, Map<String, String> extended, byte[] data) {
        public String text() {
            return new String(data, StandardCharsets.UTF_8);
        }
    }

    private static final int BLOCK = 512;

    private TarEntries() {
    }

    /** Every entry in archive, extended headers folded into the entry they precede. */
    public static List<Entry> read(byte[] archive) {
        if (archive.length % BLOCK != 0)
            throw new AssertionError("The archive is " + archive.length + " bytes, not whole blocks.");

        var entries = new ArrayList<Entry>();
        Map<String, String> extended = Map.of();
        var position = 0;
        while (true) {
            if (position + 2 * BLOCK > archive.length)
                throw new AssertionError("The archive doesn't end with two zero blocks.");
            var header = Arrays.copyOfRange(archive, position, position + BLOCK);
            if (isZero(header)) {
                if (!isZero(Arrays.copyOfRange(archive, position + BLOCK, position + 2 * BLOCK)) || position + 2 * BLOCK != archive.length)
                    throw new AssertionError("The archive's end isn't two zero blocks.");
                if (!extended.isEmpty())
                    throw new AssertionError("An extended header precedes no entry.");
                return entries;
            }

            checkHeader(header);
            var type = (char) header[156];
            var size = (int) octal(header, 124, 12);
            var data = Arrays.copyOfRange(archive, position + BLOCK, position + BLOCK + size);
            position += BLOCK + (size + BLOCK - 1) / BLOCK * BLOCK;

            if (type == 'x') {
                extended = records(data);
                continue;
            }

            var name = extended.getOrDefault("path", text(header, 0, 100));
            entries.add(new Entry(type, name, (int) octal(header, 100, 8), octal(header, 136, 12), extended, data));
            extended = Map.of();
        }
    }

    private static void checkHeader(byte[] header) {
        if (!"ustar\0".equals(new String(header, 257, 6, StandardCharsets.US_ASCII)) || header[263] != '0' || header[264] != '0')
            throw new AssertionError("A header isn't ustar.");

        var sum = 0;
        for (var i = 0; i < BLOCK; i++)
            sum += i >= 148 && i < 156 ? ' ' : header[i] & 0xFF;
        if (sum != octal(header, 148, 8))
            throw new AssertionError("A header's checksum is wrong.");
    }

    // "<length> <key>=<value>\n" records, each length counting the whole record.
    private static Map<String, String> records(byte[] data) {
        var records = new HashMap<String, String>();
        var position = 0;
        while (position < data.length) {
            var space = indexOf(data, (byte) ' ', position);
            var length = Integer.parseInt(new String(data, position, space - position, StandardCharsets.US_ASCII));
            if (data[position + length - 1] != '\n')
                throw new AssertionError("An extended record's length is wrong.");
            var record = new String(data, space + 1, position + length - space - 2, StandardCharsets.UTF_8);
            var equals = record.indexOf('=');
            records.put(record.substring(0, equals), record.substring(equals + 1));
            position += length;
        }
        return records;
    }

    private static int indexOf(byte[] data, byte b, int from) {
        for (var i = from; i < data.length; i++) {
            if (data[i] == b)
                return i;
        }
        throw new AssertionError("An extended record has no length.");
    }

    private static String text(byte[] header, int offset, int length) {
        var end = offset;
        while (end < offset + length && header[end] != 0)
            end++;
        return new String(header, offset, end - offset, StandardCharsets.UTF_8);
    }

    private static long octal(byte[] header, int offset, int length) {
        var digits = text(header, offset, length).trim();
        return digits.isEmpty() ? 0 : Long.parseLong(digits, 8);
    }

    private static boolean isZero(byte[] block) {
        for (var b : block) {
            if (b != 0)
                return false;
        }
        return true;
    }
}
