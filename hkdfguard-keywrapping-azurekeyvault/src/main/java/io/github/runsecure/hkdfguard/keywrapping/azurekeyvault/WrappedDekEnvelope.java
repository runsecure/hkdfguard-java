package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * The wrapped-DEK format {@link AzureKeyVaultKeyWrapperImpl} writes and reads, byte for byte the
 * .NET AzureKeyVaultKeyWrapper's:
 * <pre>
 * offset  length  field
 * 0       4       magic "HGKV"
 * 4       1       format version (1)
 * 5       16      wrapping key version (Key Vault's 32 hex digits, as bytes)
 * 21      2       n, the RSA-OAEP-256 ciphertext's length (big-endian)
 * 23      n       the DEK, wrapped under that version of the wrapping key
 * 23+n    16      signing key version
 * 39+n    64      ES256 signature (r || s) by that version of the signing key
 * </pre>
 * Only key versions are stored: the vault and key names are the wrapper's own, so a key file can
 * never point it at another key. The signature covers {@link #signedData}: a domain string, the
 * wrapper's context, and every byte before the signing key version.
 */
final class WrappedDekEnvelope {
    static final byte FORMAT_VERSION = 1;
    static final int KEY_VERSION_LENGTH = 16;
    static final int SIGNATURE_LENGTH = 64;

    /** Magic, format version, wrapping key version and ciphertext length. */
    static final int HEADER_LENGTH = 4 + 1 + KEY_VERSION_LENGTH + 2;

    /** Everything besides the RSA ciphertext. */
    static final int OVERHEAD = HEADER_LENGTH + KEY_VERSION_LENGTH + SIGNATURE_LENGTH;

    private static final int MAX_FIELD_LENGTH = 0xFFFF;
    private static final byte[] MAGIC = "HGKV".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] DOMAIN = "HkdfGuard-AzureKeyVault-wrap-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final HexFormat HEX = HexFormat.of();

    private WrappedDekEnvelope() {
    }

    /** A parsed envelope: the parts, and where the signed part ends. */
    record Parts(String wrappingKeyVersion, byte[] wrappedDek, String signingKeyVersion, byte[] signature, int unsignedLength) {
    }

    /**
     * The header and ciphertext: everything the signature covers besides the domain and context.
     *
     * @throws CryptographicException the version isn't Key Vault's form, or the ciphertext is empty
     *                                or too long to encode
     */
    static byte[] buildUnsigned(String wrappingKeyVersion, byte[] wrappedDek) {
        if (wrappedDek.length == 0 || wrappedDek.length > MAX_FIELD_LENGTH)
            throw new CryptographicException("Azure Key Vault returned a " + wrappedDek.length + "-byte wrapped key.");

        var unsigned = new byte[HEADER_LENGTH + wrappedDek.length];
        System.arraycopy(MAGIC, 0, unsigned, 0, MAGIC.length);
        unsigned[4] = FORMAT_VERSION;
        writeVersion(wrappingKeyVersion, unsigned, 5);
        unsigned[21] = (byte) (wrappedDek.length >>> 8);
        unsigned[22] = (byte) wrappedDek.length;
        System.arraycopy(wrappedDek, 0, unsigned, HEADER_LENGTH, wrappedDek.length);
        return unsigned;
    }

    /** What the signing key signs: the domain, the length-prefixed context, then the first {@code length} bytes of {@code unsigned}. */
    static byte[] signedData(byte[] unsigned, int length, byte[] context) {
        var data = new byte[DOMAIN.length + 2 + context.length + length];
        System.arraycopy(DOMAIN, 0, data, 0, DOMAIN.length);
        data[DOMAIN.length] = (byte) (context.length >>> 8);
        data[DOMAIN.length + 1] = (byte) context.length;
        System.arraycopy(context, 0, data, DOMAIN.length + 2, context.length);
        System.arraycopy(unsigned, 0, data, DOMAIN.length + 2 + context.length, length);
        return data;
    }

    /**
     * Writes the complete envelope into {@code result}.
     *
     * @return the number of bytes written
     * @throws IllegalArgumentException result is too small
     * @throws CryptographicException   the version or signature isn't the expected form
     */
    static int write(byte[] unsigned, String signingKeyVersion, byte[] signature, byte[] result) {
        if (signature.length != SIGNATURE_LENGTH)
            throw new CryptographicException("Azure Key Vault returned a " + signature.length + "-byte signature; an ES256 signature is "
                    + SIGNATURE_LENGTH + ". The signing key must be an EC P-256 key.");

        var length = unsigned.length + KEY_VERSION_LENGTH + SIGNATURE_LENGTH;
        if (length > result.length)
            throw new IllegalArgumentException("The wrapped DEK is " + length + " bytes; result holds " + result.length + ".");

        // Checked before anything is written, so a refused version leaves result as it was.
        var version = versionBytes(signingKeyVersion);
        System.arraycopy(unsigned, 0, result, 0, unsigned.length);
        System.arraycopy(version, 0, result, unsigned.length, KEY_VERSION_LENGTH);
        System.arraycopy(signature, 0, result, unsigned.length + KEY_VERSION_LENGTH, SIGNATURE_LENGTH);
        return length;
    }

    /**
     * Splits an envelope into its parts, refusing anything that isn't exactly one.
     *
     * @throws CryptographicException it isn't
     */
    static Parts parse(byte[] envelope) {
        if (envelope.length < OVERHEAD + 1 || !Arrays.equals(envelope, 0, MAGIC.length, MAGIC, 0, MAGIC.length))
            throw new CryptographicException("This is not a wrapped DEK written by AzureKeyVaultKeyWrapperImpl.");
        if (envelope[4] != FORMAT_VERSION)
            throw new CryptographicException("This wrapped DEK is format version " + Byte.toUnsignedInt(envelope[4])
                    + "; only version " + FORMAT_VERSION + " is supported.");

        var wrappedLength = (Byte.toUnsignedInt(envelope[21]) << 8) | Byte.toUnsignedInt(envelope[22]);
        if (wrappedLength == 0 || envelope.length != OVERHEAD + wrappedLength)
            throw new CryptographicException("This wrapped DEK is " + envelope.length + " bytes, but its header describes "
                    + (OVERHEAD + wrappedLength) + ".");

        var unsignedLength = HEADER_LENGTH + wrappedLength;
        return new Parts(
                HEX.formatHex(envelope, 5, 5 + KEY_VERSION_LENGTH),
                Arrays.copyOfRange(envelope, HEADER_LENGTH, unsignedLength),
                HEX.formatHex(envelope, unsignedLength, unsignedLength + KEY_VERSION_LENGTH),
                Arrays.copyOfRange(envelope, unsignedLength + KEY_VERSION_LENGTH, envelope.length),
                unsignedLength);
    }

    /**
     * The UTF-8 bytes of a context, refusing one too long to length-prefix, or one that isn't
     * well-formed text (an unpaired surrogate), which .NET would encode differently.
     *
     * @throws IllegalArgumentException it is
     */
    static byte[] encodeContext(String context) {
        if (context == null)
            return new byte[0];

        ByteBuffer encoded;
        try {
            encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(context));
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("The context isn't well-formed text: it holds an unpaired surrogate.", e);
        }
        if (encoded.remaining() > MAX_FIELD_LENGTH)
            throw new IllegalArgumentException("The context is " + encoded.remaining() + " bytes in UTF-8; at most "
                    + MAX_FIELD_LENGTH + " are allowed.");

        var bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        return bytes;
    }

    private static void writeVersion(String version, byte[] destination, int offset) {
        System.arraycopy(versionBytes(version), 0, destination, offset, KEY_VERSION_LENGTH);
    }

    // Key Vault key versions are 32 hex digits; stored as the 16 bytes they spell.
    private static byte[] versionBytes(String version) {
        if (version == null || version.length() != KEY_VERSION_LENGTH * 2 || !version.chars().allMatch(HexFormat::isHexDigit))
            throw new CryptographicException("Azure Key Vault returned key version '" + version + "', not 32 hex digits.");
        return HEX.parseHex(version);
    }
}
