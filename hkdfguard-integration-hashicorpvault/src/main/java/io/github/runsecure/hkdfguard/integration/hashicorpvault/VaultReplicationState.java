package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * A cluster's replication state from an X-Vault-Index header: the sdk's WALState.
 *
 * @param cluster         the cluster's id
 * @param localIndex      the local write-ahead log index, unsigned
 * @param replicatedIndex the replicated write-ahead log index, unsigned
 */
public record VaultReplicationState(String cluster, long localIndex, long replicatedIndex) {
    /**
     * The state raw holds: base64 of v1:cluster-id:local-index:replicated-index:hmac.
     *
     * @throws IllegalArgumentException raw isn't a replication state
     */
    public static VaultReplicationState parse(String raw) {
        return parse(raw, null);
    }

    /**
     * The state raw holds; with an hmacKey, the hmac (hex HMAC-SHA256 of everything before it) is
     * verified as well.
     *
     * @throws IllegalArgumentException raw isn't a replication state, or its HMAC doesn't match
     */
    public static VaultReplicationState parse(String raw, byte[] hmacKey) {
        Objects.requireNonNull(raw, "raw");
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(raw), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Could not decode the replication state: " + e.getMessage(), e);
        }

        var lastColon = decoded.lastIndexOf(':');
        if (lastColon < 0)
            throw new IllegalArgumentException("Invalid replication state header format.");

        var state = decoded.substring(0, lastColon);
        byte[] stateHmac;
        try {
            stateHmac = HexFormat.of().parseHex(decoded.substring(lastColon + 1));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid replication state header HMAC '" + decoded.substring(lastColon + 1) + "'.", e);
        }

        if (hmacKey != null && hmacKey.length > 0 && !MessageDigest.isEqual(hmacSha256(hmacKey, state), stateHmac))
            throw new IllegalArgumentException("Invalid replication state header HMAC (mismatch).");

        var pieces = state.split(":", -1);
        if (pieces.length != 4 || !pieces[0].equals("v1") || pieces[1].isEmpty())
            throw new IllegalArgumentException("Invalid replication state header format.");

        return new VaultReplicationState(pieces[1], parseIndex(pieces[2], "local"), parseIndex(pieces[3], "replicated"));
    }

    // A ulong: digits only, as NumberStyles.None reads them.
    private static long parseIndex(String digits, String which) {
        try {
            if (digits.isEmpty() || digits.charAt(0) == '+' || digits.charAt(0) == '-')
                throw new NumberFormatException();
            return Long.parseUnsignedLong(digits);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid " + which + " index in replication state header.", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, String data) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 isn't available.", e);
        }
    }
}
