package io.github.runsecure.hkdfguard.pipeline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.runsecure.hkdfguard.pipeline.contract.TarEntries;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The PAX archive's own rules: record lengths, times, padding and headers, as .NET's TarWriter writes them. */
class PaxTarArchiveTest {
    @ParameterizedTest
    // " path=" and the line feed are 7 bytes: a 1-byte value makes an 8-byte body and a 9-byte record; a
    // 90-byte one a 97-byte body and a 99-byte record; a 91-byte one a 98-byte body, which two more
    // digits would make 100 - three digits - so the record is 101.
    @CsvSource({"1, 9", "2, 11", "90, 99", "91, 101", "92, 102"})
    void aRecordsLength_CountsItsOwnDigits(int valueLength, int expected) {
        var value = "n".repeat(valueLength);
        var record = new String(PaxTarArchive.record("path", value), StandardCharsets.UTF_8);

        assertEquals(expected + " path=" + value + "\n", record);
        assertEquals(expected, record.length());
    }

    @ParameterizedTest
    @CsvSource({"1793856587, 0, 1793856587", "1793856587, 795045700, 1793856587.7950457", "1793856587, 1, 1793856587.000000001"})
    void aTime_IsSecondsWithTheFractionTrimmed(long seconds, int nanos, String expected) {
        assertEquals(expected, PaxTarArchive.time(Instant.ofEpochSecond(seconds, nanos)));
    }

    @Test
    void eachFile_IsAnExtendedHeaderAndAUstarEntry_PaddedToBlocks_ThenTwoZeroBlocks() {
        var files = new LinkedHashMap<String, byte[]>();
        files.put("empty", new byte[0]);
        files.put("block", new byte[512]);
        files.put("odd", "x".getBytes(StandardCharsets.UTF_8));
        var modified = Instant.ofEpochSecond(1793856587, 795045700);

        var archive = PaxTarArchive.of(files, 0644, modified);

        // Per file: an extended header and its one block of records, a header, and its data's blocks.
        assertEquals((2 + 1) * 512 + (2 + 1 + 1) * 512 + (2 + 1 + 1) * 512 + 1024, archive.length);
        var entries = TarEntries.read(archive);
        assertEquals(3, entries.size());
        for (var entry : entries) {
            assertArrayEquals(files.get(entry.name()), entry.data());
            assertEquals(0644, entry.mode());
            assertEquals(1793856587, entry.mtime());
            assertEquals(Map.of("path", entry.name(), "mtime", "1793856587.7950457"), entry.extended());
        }
        // ustar's own fields: the name, the magic and version, and no owner name.
        var header = new String(archive, 1024, 512, StandardCharsets.UTF_8);
        assertEquals("empty", header.substring(0, 5));
        assertEquals("ustar\u000000", header.substring(257, 265));
        assertEquals('0', header.charAt(156));
        assertEquals("PaxHeaders/empty", new String(archive, 0, 16, StandardCharsets.UTF_8));
        assertEquals('x', (char) archive[156]);
    }
}
