package io.github.runsecure.hkdfguard.options.certificate;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.security.auth.x500.X500Principal;

/**
 * Whether two distinguished names are the same, as .NET's loader compares a store certificate's
 * subject to the one configured: decoded, ignoring case, whole - never as a substring.
 *
 * <p>Compared attribute by attribute from their encodings: the same relative distinguished names in
 * the same order, each RDN's attributes as a set (so "CN=a+O=b" is "O=b+CN=a"), each attribute by
 * its OID, and each value, when it is a string type - UTF8String, PrintableString, IA5String,
 * BMPString and the rest - decoded and compared ignoring case, so how either side encodes it doesn't
 * matter. Values of any other type are compared byte for byte.
 *
 * <p>Not X500Principal's CANONICAL form, which leaves the values of attributes it has no keyword for
 * as hex: DC, emailAddress and serialNumber would then match only in the same case, and an
 * Active Directory subject "DC=Contoso, DC=com" wouldn't match "dc=contoso, dc=com". Nor its
 * whitespace folding: "CN=a  b" (two spaces) doesn't match "CN=a b", as in .NET.
 */
final class DistinguishedNames {
    private static final Charset UTF_32BE = Charset.forName("UTF-32BE");

    private DistinguishedNames() {
    }

    /** One attribute: its OID's encoding, and its value - decoded when it is a string, else its tag and contents. */
    private record Attribute(byte[] oid, String text, byte[] raw) {
        boolean matches(Attribute other) {
            if (!Arrays.equals(oid, other.oid))
                return false;
            if (text != null && other.text != null)
                return text.equalsIgnoreCase(other.text);
            return text == null && other.text == null && Arrays.equals(raw, other.raw);
        }
    }

    /** Whether {@code a} and {@code b} name the same subject. */
    static boolean equal(X500Principal a, X500Principal b) {
        List<List<Attribute>> first;
        List<List<Attribute>> second;
        try {
            first = parse(a.getEncoded());
            second = parse(b.getEncoded());
        } catch (IllegalArgumentException e) {
            // A name this reader can't take apart: only identical encodings match.
            return Arrays.equals(a.getEncoded(), b.getEncoded());
        }
        if (first.size() != second.size())
            return false;
        for (var i = 0; i < first.size(); i++) {
            if (!sameSet(first.get(i), second.get(i)))
                return false;
        }
        return true;
    }

    private static boolean sameSet(List<Attribute> first, List<Attribute> second) {
        if (first.size() != second.size())
            return false;
        var unmatched = new ArrayList<>(second);
        for (var attribute : first) {
            var found = false;
            for (var iterator = unmatched.iterator(); iterator.hasNext();) {
                if (attribute.matches(iterator.next())) {
                    iterator.remove();
                    found = true;
                    break;
                }
            }
            if (!found)
                return false;
        }
        return true;
    }

    // Name ::= SEQUENCE OF RelativeDistinguishedName; RDN ::= SET OF AttributeTypeAndValue;
    // AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }.
    private static List<List<Attribute>> parse(byte[] encoded) {
        var name = Der.parse(encoded);
        if (name.tag() != Der.SEQUENCE)
            throw new IllegalArgumentException("A name isn't a SEQUENCE.");
        var rdns = new ArrayList<List<Attribute>>();
        for (var rdn : name.children()) {
            if (rdn.tag() != Der.SET)
                throw new IllegalArgumentException("An RDN isn't a SET.");
            var attributes = new ArrayList<Attribute>();
            for (var pair : rdn.children()) {
                var parts = pair.children();
                if (pair.tag() != Der.SEQUENCE || parts.size() != 2 || parts.get(0).tag() != Der.OBJECT_IDENTIFIER)
                    throw new IllegalArgumentException("An attribute isn't a type and a value.");
                var value = parts.get(1);
                var text = decode(value);
                var raw = text == null ? withTag(value) : null;
                attributes.add(new Attribute(parts.get(0).contents(), text, raw));
            }
            rdns.add(attributes);
        }
        return rdns;
    }

    // A value's tag and contents: two values match byte for byte only with the same type.
    private static byte[] withTag(Der.Value value) {
        var raw = new byte[value.length() + 1];
        raw[0] = (byte) value.tag();
        System.arraycopy(value.buffer(), value.offset(), raw, 1, value.length());
        return raw;
    }

    // A string type's value, decoded; null for any other type.
    private static String decode(Der.Value value) {
        var contents = value.contents();
        return switch (value.tag()) {
            case 0x0C -> new String(contents, StandardCharsets.UTF_8); // UTF8String
            case 0x12, 0x13, 0x16, 0x1A -> new String(contents, StandardCharsets.US_ASCII); // Numeric, Printable, IA5, Visible
            case 0x14 -> new String(contents, StandardCharsets.ISO_8859_1); // TeletexString, as the JDK reads it
            case 0x1E -> new String(contents, StandardCharsets.UTF_16BE); // BMPString
            case 0x1C -> new String(contents, UTF_32BE); // UniversalString
            default -> null;
        };
    }
}
