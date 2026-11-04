package io.github.runsecure.hkdfguard.options.certificate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Just enough of a DER reader for what the JDK doesn't expose: the attributes of a distinguished
 * name, and a PKCS#8 key's algorithm. Single-byte tags and definite lengths only, as DER has.
 */
final class Der {
    static final int SEQUENCE = 0x30;
    static final int SET = 0x31;
    static final int OBJECT_IDENTIFIER = 0x06;

    private Der() {
    }

    /** One TLV: its tag, and where its contents are within {@code buffer}. */
    record Value(int tag, byte[] buffer, int offset, int length) {
        /** The values this constructed value holds, in order. */
        List<Value> children() {
            var children = new ArrayList<Value>();
            var position = offset;
            while (position < offset + length) {
                var child = read(buffer, position, offset + length);
                children.add(child);
                position = child.offset + child.length;
            }
            return children;
        }

        /** A copy of the contents. */
        byte[] contents() {
            return Arrays.copyOfRange(buffer, offset, offset + length);
        }

        /** Whether this is an OBJECT IDENTIFIER whose contents are {@code oid}'s. */
        boolean isOid(byte[] oid) {
            return tag == OBJECT_IDENTIFIER && Arrays.equals(buffer, offset, offset + length, oid, 0, oid.length);
        }
    }

    /** The value starting at {@code position}, which must end by {@code end}. */
    static Value read(byte[] buffer, int position, int end) {
        if (position + 2 > end)
            throw new IllegalArgumentException("Truncated DER.");
        var tag = buffer[position] & 0xFF;
        if ((tag & 0x1F) == 0x1F)
            throw new IllegalArgumentException("DER multi-byte tags aren't supported.");
        var first = buffer[position + 1] & 0xFF;
        var cursor = position + 2;
        int length;
        if (first < 0x80) {
            length = first;
        } else {
            var count = first & 0x7F;
            if (count == 0 || count > 3 || cursor + count > end)
                throw new IllegalArgumentException("A DER length is malformed.");
            length = 0;
            for (var i = 0; i < count; i++)
                length = (length << 8) | (buffer[cursor++] & 0xFF);
        }
        if (length > end - cursor)
            throw new IllegalArgumentException("A DER value runs past its end.");
        return new Value(tag, buffer, cursor, length);
    }

    /** The whole of {@code encoded}, which must be exactly one value. */
    static Value parse(byte[] encoded) {
        var value = read(encoded, 0, encoded.length);
        if (value.offset() + value.length() != encoded.length)
            throw new IllegalArgumentException("DER has trailing data.");
        return value;
    }
}
