package io.github.runsecure.hkdfguard.options.certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.api.Test;

/** How a configured subject is compared to a certificate's: decoded, ignoring case, whole. */
class DistinguishedNamesTest {
    private static boolean equal(String a, String b) {
        return DistinguishedNames.sameName(new X500Principal(a), new X500Principal(b));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "CN=api.example.com, O=Contoso | cn=API.example.com,o=contoso",
        "CN=api.example.com, O=Contoso | CN=api.example.com,O=Contoso",
        "DC=Contoso, DC=com | dc=contoso, dc=COM", // IA5String: X500Principal's CANONICAL form compares these as hex
        "EMAILADDRESS=Admin@Example.com | emailaddress=admin@example.COM",
        "SERIALNUMBER=AB12 | serialnumber=ab12",
        "CN=a+O=b | O=b+CN=a", // an RDN is a set
        "2.5.4.3=api.example.com | CN=api.example.com",
        "CN=Ünïcode | cn=ünïcode",
        "'CN=a\\,b' | 'CN=\"a,b\"'",
    })
    void theSameName_Matches(String a, String b) {
        assertTrue(equal(a, b), a + " vs " + b);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "CN=api | CN=api.example.com", // never a substring
        "CN=api.example.com | CN=api.example.com, O=Contoso", // nor a prefix of the RDNs
        "O=Contoso, CN=api.example.com | CN=api.example.com, O=Contoso", // RDN order matters
        "OU=Contoso | O=Contoso", // another attribute
        "CN=a  b | CN=a b", // whitespace isn't folded, as in .NET
        "CN=a+O=b | CN=a, O=b",
    })
    void anotherName_DoesNot(String a, String b) {
        assertFalse(equal(a, b), a + " vs " + b);
    }

    @Test
    void howACertificateEncodesItsStrings_DoesntMatter() {
        // PrintableString and BMPString in the certificate; X500Principal encodes the configured
        // subject as UTF8String/PrintableString.
        var subject = TestCertificates.name(TestCertificates.CN, 0x13, "api.example.com", TestCertificates.O, 0x1E, "Contoso");
        var certificate = TestCertificates.selfSigned(TestCertificates.ec(), subject, Instant.now().minusSeconds(60), Instant.now().plusSeconds(60));

        // Reversed by X500Principal's string form: the last RDN in DER comes first.
        assertTrue(DistinguishedNames.sameName(certificate.getSubjectX500Principal(), new X500Principal("o=CONTOSO, cn=API.example.com")));
        assertFalse(DistinguishedNames.sameName(certificate.getSubjectX500Principal(), new X500Principal("CN=api.example.com, O=Contoso")));
    }

    @Test
    void aNonStringValue_IsComparedByteForByte() {
        // A value given as hex DER: an OCTET STRING, not a string type.
        assertTrue(equal("1.2.3.4=#0403414243", "1.2.3.4=#0403414243"));
        assertFalse(equal("1.2.3.4=#0403414243", "1.2.3.4=#0403616263"));
    }
}
