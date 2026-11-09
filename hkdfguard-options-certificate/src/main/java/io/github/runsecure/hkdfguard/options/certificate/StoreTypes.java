package io.github.runsecure.hkdfguard.options.certificate;

/**
 * Which JDK KeyStore type opens a store, by .NET's StoreLocation and StoreName; the one place the
 * mapping lives, for the validator to refuse what Java can't open and the loader to open the rest.
 *
 * <p>Windows (SunMSCAPI, JDK 19+): Windows-MY-CURRENTUSER, Windows-MY-LOCALMACHINE,
 * Windows-ROOT-CURRENTUSER and Windows-ROOT-LOCALMACHINE - the My and Root system stores, in either
 * location. The JDK has no KeyStore for any other store.
 *
 * <p>macOS (the Apple provider): KeychainStore enumerates the identities and certificates of the
 * user's keychain search list - SecIdentitySearchCreate and SecKeychainSearchCreateFromAttributes
 * with no keychain given, so the login keychain, the System keychain and any other on the list, a
 * certificate without a key only when user or admin trust settings trust it (or it is self-signed
 * with none) - which is CurrentUser My. KeychainStore-ROOT reads only Apple's
 * /System/Library/Keychains/SystemRootCertificates.keychain, less any certificate distrusted in the
 * user, admin or system trust settings, which is LocalMachine Root. No type opens only the System
 * keychain (LocalMachine My: KeychainStore would also search the user's own, writable, login
 * keychain) or only the user's trust settings (CurrentUser Root), so those are refused.
 */
final class StoreTypes {
    private StoreTypes() {
    }

    /** The KeyStore type for a Windows store; {@code null} for a store the JDK can't open. */
    static String windows(StoreLocation location, StoreName name) {
        if (location == null || (name != StoreName.MY && name != StoreName.ROOT))
            return null;
        return "Windows-" + (name == StoreName.MY ? "MY" : "ROOT") + "-" + (location == StoreLocation.CURRENT_USER ? "CURRENTUSER" : "LOCALMACHINE");
    }

    /** The KeyStore type for a macOS keychain store; {@code null} for one the JDK can't open. */
    static String macOS(StoreLocation location, StoreName name) {
        if (location == StoreLocation.CURRENT_USER && name == StoreName.MY)
            return "KeychainStore";
        if (location == StoreLocation.LOCAL_MACHINE && name == StoreName.ROOT)
            return "KeychainStore-ROOT";
        return null;
    }

    /** An enum constant as .NET names it: CURRENT_USER is "CurrentUser", MY is "My". */
    static String display(Enum<?> value) {
        if (value == null)
            return "null";
        var name = new StringBuilder();
        for (var part : value.name().split("_"))
            name.append(part.charAt(0)).append(part.substring(1).toLowerCase(java.util.Locale.ROOT));
        return name.toString();
    }
}
