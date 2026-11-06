package io.github.runsecure.hkdfguard.integration.hashicorpvault;

/** The User-Agent every request carries: library/version (OS; architecture; runtime), as vault-client-go's. */
final class VaultUserAgent {
    static final String VALUE = create(version(), System.getProperty("os.name", "") + " " + System.getProperty("os.version", ""),
            System.getProperty("os.arch", ""), Runtime.version().toString());

    private VaultUserAgent() {
    }

    static String create(String version, String os, String architecture, String runtime) {
        if (version == null || version.isEmpty())
            version = "0.0.0";
        var agent = "hkdfguard-integration-hashicorpvault/" + version + " (" + os.strip() + "; " + architecture + "; Java " + runtime + ")";

        // Only what a header can carry: an OS description could hold anything.
        var chars = agent.toCharArray();
        for (var i = 0; i < chars.length; i++) {
            if (chars[i] < ' ' || chars[i] > '~')
                chars[i] = ' ';
        }
        return new String(chars);
    }

    // The module's version if it was built with one, else the jar manifest's.
    private static String version() {
        var descriptor = VaultClient.class.getModule().getDescriptor();
        if (descriptor != null && descriptor.rawVersion().isPresent())
            return descriptor.rawVersion().get();
        return VaultClient.class.getPackage().getImplementationVersion();
    }
}
