package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * A Key Vault key identifier, {@code https://{vault}/keys/{name}[/{version}]}, parsed strictly: the
 * SDK's own KeyVaultKeyIdentifier accepts any two- or three-segment path (a secret's, say) and drops
 * the port, and this one decides which keys a wrapper is pinned to.
 *
 * @param vault   the vault's URL, scheme, host and any port, without a trailing slash; the host in lower case
 * @param name    the key's name
 * @param version the key's version, or null for its current one
 */
record KeyVaultKeyId(String vault, String name, String version) {
    // Key Vault's own rules: names are 1-127 letters, digits and dashes; versions are 32 hex digits
    // in Key Vault and Managed HSM alike, but only their characters are checked here: a version
    // recorded in a wrapped DEK must be exactly 32 (see WrappedDekEnvelope).
    private static final Pattern NAME_PATTERN = Pattern.compile("[0-9A-Za-z-]{1,127}");
    private static final Pattern VERSION_PATTERN = Pattern.compile("[0-9A-Za-z]{1,64}");

    /**
     * Parses a key identifier.
     *
     * @throws IllegalArgumentException it isn't a Key Vault key's
     */
    static KeyVaultKeyId parse(String keyId) {
        URI uri;
        try {
            uri = new URI(keyId);
        } catch (URISyntaxException e) {
            throw invalid(keyId, e);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
                || uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getRawPath() == null)
            throw invalid(keyId, null);

        var path = uri.getRawPath();
        if (path.endsWith("/"))
            path = path.substring(0, path.length() - 1);
        var segments = path.split("/", -1);
        if ((segments.length != 3 && segments.length != 4) || !segments[0].isEmpty() || !"keys".equals(segments[1])
                || !NAME_PATTERN.matcher(segments[2]).matches() || (segments.length == 4 && !VERSION_PATTERN.matcher(segments[3]).matches()))
            throw invalid(keyId, null);

        var vault = "https://" + uri.getHost().toLowerCase(Locale.ROOT) + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
        return new KeyVaultKeyId(vault, segments[2], segments.length == 4 ? segments[3] : null);
    }

    /** The same key, at {@code version}. */
    KeyVaultKeyId withVersion(String version) {
        return new KeyVaultKeyId(vault, name, version);
    }

    /** Whether {@code other} names the same key, in any version: Key Vault's host and key names ignore case. */
    boolean sameKey(KeyVaultKeyId other) {
        return vault.equals(other.vault) && name.equalsIgnoreCase(other.name);
    }

    /** The identifier, as the Key Vault clients are given it. */
    @Override
    public String toString() {
        return vault + "/keys/" + name + (version == null ? "" : "/" + version);
    }

    private static IllegalArgumentException invalid(String keyId, Throwable cause) {
        return new IllegalArgumentException("'" + keyId + "' isn't a Key Vault key identifier: https://{vault}.vault.azure.net/keys/{name}, "
                + "optionally followed by /{version}.", cause);
    }
}
