package io.github.runsecure.hkdfguard.options.certificate;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;

/**
 * Validates a {@link CertificateOptions} instance before anything is opened: exactly one source
 * set, and one this operating system has - the Windows store on Windows, a keychain on macOS, an
 * OpenSSL provider's certificate on Linux, a file anywhere - with a store, subject, provider, key or
 * path that is one. A file holding a private key must be protected by a password, named by its
 * secret, unless an unprotected key is explicitly allowed.
 *
 * <p>On top of .NET's rules, it refuses what the JDK can't open, so a configuration that would fail
 * at load time fails here, with the reason:
 * <ul>
 * <li><b>Windows</b>: only the {@link StoreName#MY My} and {@link StoreName#ROOT Root} stores, in
 * either location - SunMSCAPI's Windows-MY-CURRENTUSER, Windows-MY-LOCALMACHINE,
 * Windows-ROOT-CURRENTUSER and Windows-ROOT-LOCALMACHINE KeyStores.</li>
 * <li><b>macOS</b>: CurrentUser My is the Apple provider's KeychainStore (the user's keychain search
 * list: the login keychain, the System keychain and any other on it); LocalMachine Root is
 * KeychainStore-ROOT (Apple's system roots). Every other combination is refused: no JDK KeyStore
 * opens the System keychain alone, or the user's trust settings alone. A private key is refused too:
 * KeychainStore hands one over only by exporting it from the keychain into the process, so on macOS
 * only a certificate without its key ({@code requirePrivateKey} false) can be loaded.</li>
 * <li><b>Linux</b>: the JDK has nothing like OpenSSL providers, so only the certificate file itself
 * can be loaded ({@code requirePrivateKey} false).</li>
 * </ul>
 * Those checks apply on the source's own platform; elsewhere the source is refused for being on the
 * wrong platform alone.
 */
public final class CertificateOptionsValidator {
    private final Platform platform;

    /** A validator for the operating system the process runs on. */
    public CertificateOptionsValidator() {
        this(Platform.current());
    }

    /** A validator for {@code platform}, for tests. */
    CertificateOptionsValidator(Platform platform) {
        this.platform = platform;
    }

    /**
     * Checks options against every rule.
     *
     * @param options the options to check
     * @return every failure, in the order found; empty if the options are valid
     * @throws NullPointerException {@code options} is null
     */
    public List<String> validate(CertificateOptions options) {
        Objects.requireNonNull(options, "options");
        var failures = new ArrayList<String>();

        record Source(String name, Object value, Platform platform) {
        }
        var sources = new Source[] {
            new Source("Windows", options.getWindows(), Platform.WINDOWS),
            new Source("MacOS", options.getMacOS(), Platform.MACOS),
            new Source("Linux", options.getLinux(), Platform.LINUX),
            new Source("File", options.getFile(), null),
        };
        var set = new ArrayList<Source>();
        for (var source : sources) {
            if (source.value() != null)
                set.add(source);
        }

        if (set.isEmpty())
            failures.add("One certificate source is required: Windows, MacOS, Linux or File.");
        else if (set.size() > 1)
            failures.add("Only one certificate source can be set, but " + String.join(", ", set.stream().map(Source::name).toList()) + " are.");

        for (var source : set) {
            if (source.platform() != null && source.platform() != platform)
                failures.add("The " + source.name() + " certificate source can only be used on " + source.name() + "; this is "
                        + platform.description() + ".");
        }

        if (options.getWindows() != null)
            validateWindows(options.getWindows(), failures);
        if (options.getMacOS() != null)
            validateMacOS(options.getMacOS(), options.isRequirePrivateKey(), failures);
        if (options.getLinux() != null)
            validateLinux(options.getLinux(), options.isRequirePrivateKey(), failures);
        if (options.getFile() != null)
            validateFile(options.getFile(), options.isRequirePrivateKey(), failures);

        return failures;
    }

    /**
     * Throws unless options are valid.
     *
     * @param name    the options' name, for named options, reported in the exception; {@code null} for unnamed ones
     * @param options the options to check
     * @return {@code options}, for chaining
     * @throws NullPointerException                  {@code options} is null
     * @throws CertificateOptionsValidationException any rule is broken; it lists every failure
     */
    public CertificateOptions requireValid(String name, CertificateOptions options) {
        var failures = validate(options);
        if (!failures.isEmpty())
            throw new CertificateOptionsValidationException(name, failures);
        return options;
    }

    private void validateWindows(CertificateStoreOptions store, List<String> failures) {
        validateStore("Windows", store, failures);
        if (platform == Platform.WINDOWS && store.getStoreLocation() != null && store.getStoreName() != null
                && StoreTypes.windows(store.getStoreLocation(), store.getStoreName()) == null)
            failures.add("Windows.StoreName must be My or Root on Java, not " + StoreTypes.display(store.getStoreName())
                    + ": the JDK's SunMSCAPI provider opens only the My and Root stores (its Windows-MY-* and Windows-ROOT-* KeyStores).");
    }

    private void validateMacOS(CertificateStoreOptions store, boolean requirePrivateKey, List<String> failures) {
        validateStore("MacOS", store, failures);
        if (platform != Platform.MACOS)
            return;
        if (store.getStoreLocation() != null && store.getStoreName() != null && StoreTypes.macOS(store.getStoreLocation(), store.getStoreName()) == null)
            failures.add("MacOS can't open the " + StoreTypes.display(store.getStoreLocation()) + " " + StoreTypes.display(store.getStoreName())
                    + " store on Java: the JDK's Apple provider opens only CurrentUser My (KeychainStore, the user's keychain search list) "
                    + "and LocalMachine Root (KeychainStore-ROOT, the system's root certificates).");
        if (requirePrivateKey)
            failures.add("MacOS can't open a certificate's private key on Java without exporting it: the JDK's KeychainStore hands over a key only by "
                    + "exporting it from the keychain into the process. Set RequirePrivateKey to false to load the certificate alone, or use a File source.");
    }

    private static void validateStore(String source, CertificateStoreOptions store, List<String> failures) {
        if (store.getStoreLocation() == null)
            failures.add(source + ".StoreLocation must be CurrentUser or LocalMachine, not null.");
        if (store.getStoreName() == null)
            failures.add(source + ".StoreName must be a store's name - My, Root, CertificateAuthority, TrustedPeople... - not null.");

        var subject = store.getSubject();
        if (subject == null || subject.isBlank()) {
            failures.add(source + ".Subject is required: the certificate's subject distinguished name, e.g. \"CN=api.example.com\".");
            return;
        }

        try {
            new X500Principal(subject);
        } catch (IllegalArgumentException e) {
            failures.add(source + ".Subject must be a distinguished name, e.g. \"CN=api.example.com, O=Contoso\", not '" + subject + "'.");
        }
    }

    private void validateLinux(LinuxOpenSslProviderOptions linux, boolean requirePrivateKey, List<String> failures) {
        var provider = linux.getProvider();
        if (provider == null || provider.isEmpty() || !provider.chars().allMatch(c -> isAsciiLetterOrDigit(c) || c == '-' || c == '_'))
            failures.add("Linux.Provider must be an OpenSSL provider's name - \"tpm2\" or \"pkcs11\" - not '" + provider + "'.");
        if (requirePrivateKey && (linux.getKeyUri() == null || linux.getKeyUri().isBlank()))
            failures.add("Linux.KeyUri is required: the key as the provider names it, e.g. \"handle:0x81000001\".");
        validatePath("Linux.CertificateFile", linux.getCertificateFile(), failures);
        if (requirePrivateKey && platform == Platform.LINUX)
            failures.add("Linux can't open an OpenSSL provider's key on Java: the JDK has no counterpart to OpenSSL 3 providers (SunPKCS11 is "
                    + "configured with a PKCS#11 library, not a provider and key URI). Set RequirePrivateKey to false to load the certificate "
                    + "alone, or use a File source.");
    }

    private static void validateFile(CertificateFileOptions file, boolean requirePrivateKey, List<String> failures) {
        validatePath("File.Path", file.getPath(), failures);

        if (file.getFormat() == null)
            failures.add("File.Format must be Pkcs12 or Pem, not null.");
        else if (file.getFormat() == CertificateFileFormat.PEM && requirePrivateKey)
            validatePath("File.KeyPath", file.getKeyPath(), failures);

        var passwordSecretName = file.getPasswordSecretName();
        if (passwordSecretName != null && passwordSecretName.isBlank())
            failures.add("File.PasswordSecretName can't be empty: name the secret holding the key's password, or leave it unset.");
        else if (requirePrivateKey && passwordSecretName == null && !file.isAllowUnprotectedPrivateKey())
            failures.add("File.PasswordSecretName is required: a private key file must be protected by a password, read from a protected secret. "
                    + "Set File.AllowUnprotectedPrivateKey to accept a plaintext key, for development only.");
    }

    private static void validatePath(String what, String path, List<String> failures) {
        if (path == null || path.isBlank())
            failures.add(what + " is required.");
        else if (!isAbsolute(path))
            failures.add(what + " must be an absolute path, not '" + path + "'.");
    }

    /** Whether path is fully qualified on this operating system: "C:\x" or "\\server\share" on Windows, "/x" elsewhere. */
    static boolean isAbsolute(String path) {
        try {
            return Path.of(path).isAbsolute();
        } catch (InvalidPathException e) {
            return false;
        }
    }

    private static boolean isAsciiLetterOrDigit(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }
}
