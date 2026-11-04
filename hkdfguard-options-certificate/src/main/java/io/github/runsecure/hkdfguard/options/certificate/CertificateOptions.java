package io.github.runsecure.hkdfguard.options.certificate;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * Plain-data description of where one certificate - with its private key - is opened from: exactly
 * one of the operating system's own protected key storage ({@link #getWindows() windows},
 * {@link #getMacOS() macOS}, {@link #getLinux() linux}) or a key file on the filesystem
 * ({@link #getFile() file}). It carries no behavior and never a password: a file's password is named
 * here, and read at load time from a protected secret source, so it is never plaintext on disk or in
 * configuration. Validate it with {@link CertificateOptionsValidator}, and open it with
 * {@link CertificateOptionsLoader}; for several certificates, keep one instance per name.
 *
 * <pre>{@code
 * "Certificate": { "Windows": { "StoreLocation": "LocalMachine", "StoreName": "My", "Subject": "CN=api.example.com" } }
 * "Certificate": { "MacOS": { "StoreLocation": "CurrentUser", "Subject": "CN=api.example.com" }, "RequirePrivateKey": false }
 * "Certificate": { "File": { "Path": "/etc/myapp/tls.pfx", "PasswordSecretName": "tls-pfx-password" } }
 * }</pre>
 *
 * <p>A JavaBean, so a configuration binder can populate it directly - Spring's
 * {@code @ConfigurationProperties}, Jackson, MicroProfile Config. Without one, {@link #fromMap(Map)}
 * reads a parsed configuration section, the same JSON shape .NET's binder reads. Not thread-safe:
 * populate it, then share it only once it is no longer changed.
 */
public final class CertificateOptions {
    private static final List<String> FIELDS = List.of("windows", "macOS", "linux", "file", "requirePrivateKey");
    private static final List<String> STORE_FIELDS = List.of("storeLocation", "storeName", "subject");
    private static final List<String> LINUX_FIELDS = List.of("provider", "keyUri", "certificateFile");
    private static final List<String> FILE_FIELDS = List.of("path", "format", "keyPath", "passwordSecretName", "allowUnprotectedPrivateKey");

    private CertificateStoreOptions windows;
    private CertificateStoreOptions macOS;
    private LinuxOpenSslProviderOptions linux;
    private CertificateFileOptions file;
    private boolean requirePrivateKey = true;

    /** Options with no source set, requiring a private key. */
    public CertificateOptions() {
    }

    /** {@return a certificate in a Windows certificate store, its key held by CNG or CryptoAPI; or {@code null}} */
    public CertificateStoreOptions getWindows() {
        return windows;
    }

    /**
     * Sets a certificate in a Windows certificate store.
     *
     * @param windows a certificate in a Windows certificate store
     */
    public void setWindows(CertificateStoreOptions windows) {
        this.windows = windows;
    }

    /** {@return a certificate in a macOS keychain; or {@code null}} */
    public CertificateStoreOptions getMacOS() {
        return macOS;
    }

    /**
     * Sets a certificate in a macOS keychain.
     *
     * @param macOS a certificate in a macOS keychain
     */
    public void setMacOS(CertificateStoreOptions macOS) {
        this.macOS = macOS;
    }

    /**
     * A certificate whose key is opened through an OpenSSL 3 provider on Linux - the TPM, say. On
     * Java only its certificate can be loaded: see {@link LinuxOpenSslProviderOptions}.
     *
     * @return the Linux provider source, or {@code null}
     */
    public LinuxOpenSslProviderOptions getLinux() {
        return linux;
    }

    /**
     * Sets a certificate whose key is held by an OpenSSL provider on Linux.
     *
     * @param linux a certificate whose key is held by an OpenSSL provider on Linux
     */
    public void setLinux(LinuxOpenSslProviderOptions linux) {
        this.linux = linux;
    }

    /** {@return a certificate and key read from files, the key protected by a password; or {@code null}} */
    public CertificateFileOptions getFile() {
        return file;
    }

    /**
     * Sets a certificate and key read from files.
     *
     * @param file a certificate and key read from files
     */
    public void setFile(CertificateFileOptions file) {
        this.file = file;
    }

    /**
     * Whether the certificate must come with its private key: true (the default) for one presented
     * as a TLS server or client certificate, or used to sign; false for one only to be trusted.
     *
     * @return whether the private key is required
     */
    public boolean isRequirePrivateKey() {
        return requirePrivateKey;
    }

    /**
     * Sets whether the certificate must come with its private key.
     *
     * @param requirePrivateKey whether the certificate must come with its private key
     */
    public void setRequirePrivateKey(boolean requirePrivateKey) {
        this.requirePrivateKey = requirePrivateKey;
    }

    // --- Reading configuration -------------------------------------------------------------------

    /**
     * Reads options from a parsed configuration section - a {@code Map} from JSON, YAML or TOML.
     *
     * <p>As {@code HkdfGuardOptions.fromMap} does, keys match a property ignoring case, underscores
     * and hyphens, so a .NET {@code appsettings.json} section ({@code "Windows": {"StoreLocation":
     * "LocalMachine"}}), camelCase, snake_case and kebab-case all read; enum values match the same
     * way ({@code "LocalMachine"}, {@code "LOCAL_MACHINE"}, {@code "local-machine"}). Booleans may
     * also be strings. A {@code null} value leaves its property unset. The result is not validated:
     * check it with {@link CertificateOptionsValidator}, as {@link CertificateOptionsLoader} does.
     *
     * @param settings the configuration section
     * @return the options it describes
     * @throws NullPointerException     {@code settings} is null
     * @throws IllegalArgumentException an unknown key (a likely typo, never silently ignored), a key
     *                                  given twice, or a value of the wrong type; the message names
     *                                  where
     */
    public static CertificateOptions fromMap(Map<String, ?> settings) {
        Objects.requireNonNull(settings, "settings");
        var reader = new Reader(settings, "settings", FIELDS);
        var options = new CertificateOptions();
        options.windows = reader.read("windows", CertificateOptions::store);
        options.macOS = reader.read("macOS", CertificateOptions::store);
        options.linux = reader.read("linux", CertificateOptions::linux);
        options.file = reader.read("file", CertificateOptions::file);
        var require = reader.read("requirePrivateKey", CertificateOptions::bool);
        if (require != null)
            options.requirePrivateKey = require;
        return options;
    }

    private static CertificateStoreOptions store(Object value, String where) {
        if (value instanceof CertificateStoreOptions store)
            return store;
        var reader = new Reader(value, where, STORE_FIELDS);
        var store = new CertificateStoreOptions();
        var location = reader.read("storeLocation", (v, w) -> enumValue(StoreLocation.class, v, w));
        if (location != null)
            store.setStoreLocation(location);
        var name = reader.read("storeName", (v, w) -> enumValue(StoreName.class, v, w));
        if (name != null)
            store.setStoreName(name);
        store.setSubject(reader.read("subject", CertificateOptions::string));
        return store;
    }

    private static LinuxOpenSslProviderOptions linux(Object value, String where) {
        if (value instanceof LinuxOpenSslProviderOptions linux)
            return linux;
        var reader = new Reader(value, where, LINUX_FIELDS);
        var linux = new LinuxOpenSslProviderOptions();
        var provider = reader.read("provider", CertificateOptions::string);
        if (provider != null)
            linux.setProvider(provider);
        linux.setKeyUri(reader.read("keyUri", CertificateOptions::string));
        linux.setCertificateFile(reader.read("certificateFile", CertificateOptions::string));
        return linux;
    }

    private static CertificateFileOptions file(Object value, String where) {
        if (value instanceof CertificateFileOptions file)
            return file;
        var reader = new Reader(value, where, FILE_FIELDS);
        var file = new CertificateFileOptions();
        file.setPath(reader.read("path", CertificateOptions::string));
        var format = reader.read("format", (v, w) -> enumValue(CertificateFileFormat.class, v, w));
        if (format != null)
            file.setFormat(format);
        file.setKeyPath(reader.read("keyPath", CertificateOptions::string));
        file.setPasswordSecretName(reader.read("passwordSecretName", CertificateOptions::string));
        file.setAllowUnprotectedPrivateKey(Boolean.TRUE.equals(reader.read("allowUnprotectedPrivateKey", CertificateOptions::bool)));
        return file;
    }

    private static String normalize(String key) {
        return key.replace("_", "").replace("-", "").toLowerCase(Locale.ROOT);
    }

    /** A configuration section's values by property name, matched ignoring case, '_' and '-'. */
    private static final class Reader {
        private final Map<String, Object> values = new HashMap<>();
        private final String where;

        Reader(Object section, String where, List<String> fields) {
            if (!(section instanceof Map<?, ?> map))
                throw new IllegalArgumentException(where + " must be a map; it is " + typeName(section) + ".");
            this.where = where;
            var known = new HashMap<String, String>();
            for (var field : fields)
                known.put(normalize(field), field);
            for (var entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key))
                    throw new IllegalArgumentException(where + " has a key that is not a string: " + entry.getKey() + ".");
                var name = known.get(normalize(key));
                if (name == null)
                    throw new IllegalArgumentException(where + " has an unknown key '" + key + "'. Known keys: " + String.join(", ", fields) + ".");
                if (values.containsKey(name))
                    throw new IllegalArgumentException(where + " gives '" + name + "' more than once.");
                values.put(name, entry.getValue());
            }
        }

        <T> T read(String name, BiFunction<Object, String, T> convert) {
            var value = values.get(name);
            return value == null ? null : convert.apply(value, where + "." + name);
        }
    }

    private static String string(Object value, String where) {
        if (value instanceof String text)
            return text;
        throw new IllegalArgumentException(where + " must be a string; it is " + typeName(value) + ".");
    }

    private static Boolean bool(Object value, String where) {
        if (value instanceof Boolean flag)
            return flag;
        if (value instanceof String text && (text.strip().equalsIgnoreCase("true") || text.strip().equalsIgnoreCase("false")))
            return text.strip().equalsIgnoreCase("true");
        throw new IllegalArgumentException(where + " must be true or false; it is " + describe(value) + ".");
    }

    private static <E extends Enum<E>> E enumValue(Class<E> type, Object value, String where) {
        if (type.isInstance(value))
            return type.cast(value);
        if (value instanceof String text) {
            for (var constant : type.getEnumConstants()) {
                if (normalize(constant.name()).equals(normalize(text.strip())))
                    return constant;
            }
        }
        var names = new StringBuilder();
        for (var constant : type.getEnumConstants())
            names.append(names.isEmpty() ? "" : ", ").append(constant.name());
        throw new IllegalArgumentException(where + " must be one of " + names + "; it is " + describe(value) + ".");
    }

    private static String typeName(Object value) {
        return value == null ? "null" : value.getClass().getSimpleName();
    }

    private static String describe(Object value) {
        return value instanceof String text ? "'" + text + "'" : value + " (" + typeName(value) + ")";
    }

    @Override
    public String toString() {
        return "CertificateOptions[windows=" + windows + ", macOS=" + macOS + ", linux=" + linux + ", file=" + file + ", requirePrivateKey="
                + requirePrivateKey + "]";
    }
}
