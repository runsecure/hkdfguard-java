package io.github.runsecure.hkdfguard.pipeline;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

/**
 * A POSIX.1-2001 (PAX) tar archive of regular files, as .NET's TarWriter writes one in
 * TarEntryFormat.Pax: each file a ustar header and its data, preceded by an extended header
 * ('x') naming its path and its modification time to the sub-second, and the archive ended by two
 * zero blocks. GNU tar and bsdtar (macOS, and Windows' tar.exe) both read it. The JDK has no tar
 * writer, and the archive needs only this much, so it is written here rather than taken from a
 * library: every file is owned by uid and gid 0 with no user or group name, which an unpacking tar
 * run with --no-same-owner ignores.
 * <p>
 * Only for contents that aren't secret - the encrypted, formatted values - since the archive is
 * built in memory as one array.
 */
final class PaxTarArchive {
    static final int BLOCK_SIZE = 512;

    // ustar header fields: offset and length.
    private static final int NAME = 0;
    private static final int NAME_LENGTH = 100;
    private static final int MODE = 100;
    private static final int UID = 108;
    private static final int GID = 116;
    private static final int SIZE = 124;
    private static final int MTIME = 136;
    private static final int CHECKSUM = 148;
    private static final int TYPE_FLAG = 156;
    private static final int MAGIC = 257;
    private static final int VERSION = 263;
    private static final int DEV_MAJOR = 329;
    private static final int DEV_MINOR = 337;

    private static final byte REGULAR_FILE = '0';
    private static final byte EXTENDED_HEADER = 'x';

    // Where each extended header is named, as GNU tar names them; never unpacked as a file.
    private static final String EXTENDED_HEADER_FOLDER = "PaxHeaders/";

    private PaxTarArchive() {
    }

    /**
     * The archive of {@code files}, in their map's order: each entry's name to its contents, every
     * one with {@code mode} and modified at {@code modified}.
     */
    static byte[] of(Map<String, byte[]> files, int mode, Instant modified) {
        var archive = new ByteArrayOutputStream();
        for (var file : files.entrySet()) {
            var name = file.getKey().getBytes(StandardCharsets.UTF_8);
            var extended = extendedRecords(name, modified);
            writeEntry(archive, EXTENDED_HEADER, utf8(EXTENDED_HEADER_FOLDER + file.getKey()), mode, modified.getEpochSecond(), extended);
            writeEntry(archive, REGULAR_FILE, name, mode, modified.getEpochSecond(), file.getValue());
        }

        // The end of the archive: two zero blocks.
        archive.writeBytes(new byte[2 * BLOCK_SIZE]);
        return archive.toByteArray();
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    // The extended header's records: the full path, which a ustar name field may be too short for,
    // and the modification time to the sub-second.
    private static byte[] extendedRecords(byte[] name, Instant modified) {
        var records = new ByteArrayOutputStream();
        records.writeBytes(record("path", new String(name, StandardCharsets.UTF_8)));
        records.writeBytes(record("mtime", time(modified)));
        return records.toByteArray();
    }

    // "<length> <key>=<value>\n", where length counts the whole record, its own digits included.
    static byte[] record(String key, String value) {
        var body = (" " + key + "=" + value + "\n").getBytes(StandardCharsets.UTF_8);
        var length = body.length + 1;
        while (String.valueOf(length).length() + body.length != length)
            length++;

        var record = new ByteArrayOutputStream();
        record.writeBytes(utf8(String.valueOf(length)));
        record.writeBytes(body);
        return record.toByteArray();
    }

    // Seconds since the epoch, with the fraction to the nanosecond and its trailing zeros dropped.
    static String time(Instant instant) {
        if (instant.getNano() == 0)
            return String.valueOf(instant.getEpochSecond());

        var fraction = String.format("%09d", instant.getNano()).replaceAll("0+$", "");
        return instant.getEpochSecond() + "." + fraction;
    }

    private static void writeEntry(ByteArrayOutputStream archive, byte type, byte[] name, int mode, long mtime, byte[] data) {
        var header = new byte[BLOCK_SIZE];
        // A longer name is truncated here; the extended header holds it whole.
        System.arraycopy(name, 0, header, NAME, Math.min(name.length, NAME_LENGTH));
        octal(header, MODE, 8, mode);
        octal(header, UID, 8, 0);
        octal(header, GID, 8, 0);
        octal(header, SIZE, 12, data.length);
        octal(header, MTIME, 12, mtime);
        header[TYPE_FLAG] = type;
        System.arraycopy(utf8("ustar\0"), 0, header, MAGIC, 6);
        System.arraycopy(utf8("00"), 0, header, VERSION, 2);
        octal(header, DEV_MAJOR, 8, 0);
        octal(header, DEV_MINOR, 8, 0);

        // The checksum is the sum of the header's bytes with its own field as spaces, written as six
        // octal digits, a NUL and a space.
        Arrays.fill(header, CHECKSUM, CHECKSUM + 8, (byte) ' ');
        var sum = 0;
        for (var b : header)
            sum += b & 0xFF;
        var checksum = utf8(String.format("%06o", sum));
        System.arraycopy(checksum, 0, header, CHECKSUM, 6);
        header[CHECKSUM + 6] = 0;

        archive.writeBytes(header);
        archive.writeBytes(data);
        var padding = (BLOCK_SIZE - data.length % BLOCK_SIZE) % BLOCK_SIZE;
        archive.writeBytes(new byte[padding]);
    }

    // value as length - 1 zero-padded octal digits and a NUL. Every value fits: a size is at most
    // an array's length, under 8 GiB's 11 digits, and a time in seconds fits them until 2242.
    private static void octal(byte[] header, int offset, int length, long value) {
        var digits = Long.toOctalString(value);
        var field = utf8("0".repeat(length - 1 - digits.length()) + digits);
        System.arraycopy(field, 0, header, offset, field.length);
        header[offset + length - 1] = 0;
    }
}
