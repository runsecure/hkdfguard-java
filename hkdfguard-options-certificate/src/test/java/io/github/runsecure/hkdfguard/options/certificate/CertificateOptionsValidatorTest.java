package io.github.runsecure.hkdfguard.options.certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class CertificateOptionsValidatorTest {
    private static final String SUBJECT = "CN=api.example.com, O=Contoso";

    // An absolute path on the host the tests run on, as the validator checks it.
    private static final String ABSOLUTE_PATH = Path.of(System.getProperty("java.io.tmpdir"), "tls.pfx").toAbsolutePath().toString();

    private static List<String> failures(CertificateOptions options, Platform platform) {
        return new CertificateOptionsValidator(platform).validate(options);
    }

    private static String single(List<String> failures) {
        assertEquals(1, failures.size(), failures.toString());
        return failures.get(0);
    }

    private static CertificateStoreOptions storeOf(String subject) {
        var store = new CertificateStoreOptions();
        store.setSubject(subject);
        return store;
    }

    private static CertificateOptions windowsStore(String subject) {
        var options = new CertificateOptions();
        options.setWindows(storeOf(subject));
        return options;
    }

    // The macOS store Java can open: CurrentUser My, without its key.
    private static CertificateOptions macOSStore(String subject) {
        var options = new CertificateOptions();
        var store = storeOf(subject);
        store.setStoreLocation(StoreLocation.CURRENT_USER);
        options.setMacOS(store);
        options.setRequirePrivateKey(false);
        return options;
    }

    private static CertificateOptions linux(String provider, String keyUri, String certificateFile, boolean requirePrivateKey) {
        var linux = new LinuxOpenSslProviderOptions();
        if (provider != null)
            linux.setProvider(provider);
        linux.setKeyUri(keyUri);
        linux.setCertificateFile(certificateFile);
        var options = new CertificateOptions();
        options.setLinux(linux);
        options.setRequirePrivateKey(requirePrivateKey);
        return options;
    }

    private static CertificateOptions protectedFile() {
        var file = new CertificateFileOptions();
        file.setPath(ABSOLUTE_PATH);
        file.setPasswordSecretName("tls-pfx-password");
        var options = new CertificateOptions();
        options.setFile(file);
        return options;
    }

    @Test
    void eachSource_IsValid_OnItsOwnPlatform() {
        assertEquals(List.of(), failures(windowsStore(SUBJECT), Platform.WINDOWS));
        assertEquals(List.of(), failures(macOSStore(SUBJECT), Platform.MACOS));
        assertEquals(List.of(), failures(linux(null, null, ABSOLUTE_PATH, false), Platform.LINUX));
        for (var platform : Platform.values())
            assertEquals(List.of(), failures(protectedFile(), platform));
    }

    @ParameterizedTest
    @CsvSource({ "Windows, LINUX", "MacOS, WINDOWS", "Linux, MACOS" })
    void aNativeSource_IsRefused_OnAnotherPlatform(String source, Platform platform) {
        var options = switch (source) {
            case "Windows" -> windowsStore(SUBJECT);
            case "MacOS" -> macOSStore(SUBJECT);
            default -> linux(null, "handle:0x81000001", ABSOLUTE_PATH, true);
        };

        var failure = single(failures(options, platform));

        assertTrue(failure.startsWith("The " + source + " certificate source can only be used on " + source + "; this is "), failure);
    }

    @Test
    void anUnknownPlatform_IsNamedAsSuch() {
        assertTrue(single(failures(windowsStore(SUBJECT), Platform.OTHER)).endsWith("this is another operating system."));
    }

    @Test
    void noSource_OrMoreThanOne_IsRefused() {
        assertTrue(single(failures(new CertificateOptions(), Platform.WINDOWS)).contains("One certificate source is required"));

        var both = windowsStore(SUBJECT);
        both.setFile(protectedFile().getFile());
        assertTrue(failures(both, Platform.WINDOWS).contains("Only one certificate source can be set, but Windows, File are."));
    }

    @ParameterizedTest
    @ValueSource(strings = { "CN=api.example.com", "CN=api.example.com, O=Contoso, C=US", "cn=api.example.com", "2.5.4.3=api", "CN=a+O=b" })
    void aStore_TakesASubjectDistinguishedName(String subject) {
        assertEquals(List.of(), failures(windowsStore(subject), Platform.WINDOWS));
        assertEquals(List.of(), failures(macOSStore(subject), Platform.MACOS));
    }

    @ParameterizedTest
    @CsvSource(value = { "NULL, Subject is required", "' ', Subject is required", "api.example.com, must be a distinguished name",
        "'CN=a,', must be a distinguished name" }, nullValues = "NULL")
    void aStore_NeedsASubjectThatIsADistinguishedName(String subject, String reason) {
        var windows = single(failures(windowsStore(subject), Platform.WINDOWS));
        var macOS = single(failures(macOSStore(subject), Platform.MACOS));

        assertTrue(windows.startsWith("Windows.") && windows.contains(reason), windows);
        assertTrue(macOS.startsWith("MacOS.") && macOS.contains(reason), macOS);
    }

    @Test
    void aStore_NeedsAStoreLocationAndName() {
        var options = windowsStore(SUBJECT);
        options.getWindows().setStoreLocation(null);
        options.getWindows().setStoreName(null);

        var failures = failures(options, Platform.WINDOWS);

        assertEquals(2, failures.size(), failures.toString());
        assertTrue(failures.get(0).startsWith("Windows.StoreLocation"));
        assertTrue(failures.get(1).startsWith("Windows.StoreName"));
    }

    @ParameterizedTest
    @EnumSource(value = StoreName.class, names = { "MY", "ROOT" }, mode = EnumSource.Mode.EXCLUDE)
    void aWindowsStore_OtherThanMyOrRoot_IsRefused_OnJava(StoreName name) {
        for (var location : StoreLocation.values()) {
            var options = windowsStore(SUBJECT);
            options.getWindows().setStoreLocation(location);
            options.getWindows().setStoreName(name);

            var failure = single(failures(options, Platform.WINDOWS));

            assertTrue(failure.startsWith("Windows.StoreName must be My or Root on Java, not " + StoreTypes.display(name) + ":"), failure);
            // Off Windows the store is refused for its platform alone.
            assertTrue(single(failures(options, Platform.LINUX)).startsWith("The Windows certificate source can only be used on Windows"));
        }
    }

    @Test
    void theMacOSStores_JavaCantOpen_AreRefused() {
        for (var location : StoreLocation.values()) {
            for (var name : StoreName.values()) {
                var options = macOSStore(SUBJECT);
                options.getMacOS().setStoreLocation(location);
                options.getMacOS().setStoreName(name);
                var opens = (location == StoreLocation.CURRENT_USER && name == StoreName.MY) || (location == StoreLocation.LOCAL_MACHINE && name == StoreName.ROOT);

                var failures = failures(options, Platform.MACOS);

                if (opens) {
                    assertEquals(List.of(), failures);
                } else {
                    var failure = single(failures);
                    assertTrue(failure.startsWith("MacOS can't open the " + StoreTypes.display(location) + " " + StoreTypes.display(name) + " store on Java"), failure);
                }
            }
        }
    }

    @Test
    void aMacOSPrivateKey_IsRefused_SinceTheKeychainWouldExportIt() {
        var options = macOSStore(SUBJECT);
        options.setRequirePrivateKey(true);

        var failure = single(failures(options, Platform.MACOS));

        assertTrue(failure.startsWith("MacOS can't open a certificate's private key on Java without exporting it"), failure);
    }

    @Test
    void theMacOSDefaults_LocalMachineMyWithItsKey_AreRefusedTwice() {
        var options = new CertificateOptions();
        options.setMacOS(storeOf(SUBJECT));

        assertEquals(2, failures(options, Platform.MACOS).size());
    }

    @ParameterizedTest
    @ValueSource(strings = { "my-provider", "my_provider", "tpm2", "pkcs11" })
    void aLinuxProvider_MayHoldHyphensAndUnderscores(String provider) {
        assertEquals(List.of(), failures(linux(provider, "k", ABSOLUTE_PATH, false), Platform.LINUX));
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "tpm2;rm" })
    void aLinuxProvider_MustBeAProvidersName(String provider) {
        assertTrue(single(failures(linux(provider, "k", ABSOLUTE_PATH, false), Platform.LINUX)).startsWith("Linux.Provider"));
    }

    @Test
    void aLinuxKey_IsRequired_OnlyWithAPrivateKey_AndRefusedOnJava() {
        var options = linux("pkcs11", null, ABSOLUTE_PATH, true);
        var failures = failures(options, Platform.LINUX);
        assertEquals(2, failures.size(), failures.toString());
        assertTrue(failures.get(0).startsWith("Linux.KeyUri"));
        assertTrue(failures.get(1).startsWith("Linux can't open an OpenSSL provider's key on Java"));

        options.getLinux().setKeyUri("pkcs11:token=t");
        assertTrue(single(failures(options, Platform.LINUX)).startsWith("Linux can't open an OpenSSL provider's key on Java"));

        options.setRequirePrivateKey(false);
        assertEquals(List.of(), failures(options, Platform.LINUX));
    }

    @Test
    void thePlatform_IsTheFirstOperatingSystemCheckThatHolds() {
        assertSame(Platform.WINDOWS, Platform.of(true, false, false));
        assertSame(Platform.MACOS, Platform.of(false, true, false));
        assertSame(Platform.LINUX, Platform.of(false, false, true));
        assertSame(Platform.OTHER, Platform.of(false, false, false));
        var os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        assertSame(os.startsWith("windows") ? Platform.WINDOWS : os.startsWith("mac") ? Platform.MACOS : os.startsWith("linux") ? Platform.LINUX : Platform.OTHER,
                Platform.current());
    }

    @ParameterizedTest
    @CsvSource(value = { "NULL, is required", "' ', is required", "relative/tls.crt, must be an absolute path" }, nullValues = "NULL")
    void aFilePath_MustBeAbsolute(String path, String reason) {
        var file = protectedFile();
        file.getFile().setPath(path);

        assertTrue(single(failures(linux(null, "k", path, false), Platform.LINUX)).contains(reason));
        assertTrue(single(failures(file, Platform.WINDOWS)).contains(reason));
    }

    @Test
    void aWindowsPath_MustBeFullyQualified() {
        if (!System.getProperty("os.name").startsWith("Windows"))
            return;
        assertTrue(CertificateOptionsValidator.isAbsolute("C:\\certs\\tls.pfx"));
        assertTrue(CertificateOptionsValidator.isAbsolute("\\\\server\\share\\tls.pfx"));
        assertFalse(CertificateOptionsValidator.isAbsolute("\\certs\\tls.pfx"));
        assertFalse(CertificateOptionsValidator.isAbsolute("C:tls.pfx"));
        assertFalse(CertificateOptionsValidator.isAbsolute("C:\\bad\0name"));
    }

    @Test
    void aPemFile_NeedsAKeyPath_OnlyWithAPrivateKey() {
        var options = protectedFile();
        options.getFile().setFormat(CertificateFileFormat.PEM);
        assertTrue(single(failures(options, Platform.WINDOWS)).startsWith("File.KeyPath"));

        options.getFile().setKeyPath(ABSOLUTE_PATH);
        assertEquals(List.of(), failures(options, Platform.WINDOWS));

        options.getFile().setKeyPath(null);
        options.setRequirePrivateKey(false);
        assertEquals(List.of(), failures(options, Platform.WINDOWS));
    }

    @ParameterizedTest
    @NullSource
    void aFileFormat_MustBeOne(CertificateFileFormat format) {
        var options = protectedFile();
        options.getFile().setFormat(format);

        assertEquals("File.Format must be Pkcs12 or Pem, not null.", single(failures(options, Platform.WINDOWS)));
    }

    @Test
    void aKeyFile_NeedsAPassword_UnlessAnUnprotectedKeyIsAllowed() {
        var options = protectedFile();
        options.getFile().setPasswordSecretName(null);
        assertTrue(single(failures(options, Platform.WINDOWS)).contains("File.AllowUnprotectedPrivateKey"));

        options.getFile().setAllowUnprotectedPrivateKey(true);
        assertEquals(List.of(), failures(options, Platform.WINDOWS));

        options.getFile().setAllowUnprotectedPrivateKey(false);
        options.setRequirePrivateKey(false);
        assertEquals(List.of(), failures(options, Platform.WINDOWS));
    }

    @Test
    void anEmptyPasswordSecretName_IsRefused() {
        var options = protectedFile();
        options.getFile().setPasswordSecretName(" ");

        assertTrue(single(failures(options, Platform.WINDOWS)).startsWith("File.PasswordSecretName can't be empty"));
    }

    @Test
    void theValidator_ChecksForTheRunningPlatform_AndNullOptions() {
        var validator = new CertificateOptionsValidator();

        assertEquals(List.of(), validator.validate(protectedFile()));
        assertEquals(Platform.current() == Platform.WINDOWS, validator.validate(windowsStore(SUBJECT)).isEmpty());
        assertThrows(NullPointerException.class, () -> validator.validate(null));
        var options = protectedFile();
        assertSame(options, validator.requireValid("tls", options));
        var ex = assertThrows(CertificateOptionsValidationException.class, () -> validator.requireValid(null, new CertificateOptions()));
        assertEquals(List.of("One certificate source is required: Windows, MacOS, Linux or File."), ex.getFailures());
        assertEquals("Certificate options are invalid: One certificate source is required: Windows, MacOS, Linux or File.", ex.getMessage());
    }

    @Test
    void theDocumentedShapes_ReadFromAConfigurationSection() {
        var windows = CertificateOptions.fromMap(Map.of("Windows",
                Map.of("StoreLocation", "CurrentUser", "StoreName", "TrustedPeople", "Subject", "CN=api.example.com"))).getWindows();
        assertEquals(List.of(StoreLocation.CURRENT_USER, StoreName.TRUSTED_PEOPLE, "CN=api.example.com"),
                List.of(windows.getStoreLocation(), windows.getStoreName(), windows.getSubject()));

        var macOS = CertificateOptions.fromMap(Map.of("MacOS", Map.of("StoreLocation", "LocalMachine", "Subject", "CN=api.example.com"))).getMacOS();
        assertEquals(List.of(StoreLocation.LOCAL_MACHINE, StoreName.MY, "CN=api.example.com"),
                List.of(macOS.getStoreLocation(), macOS.getStoreName(), macOS.getSubject()));

        var linux = CertificateOptions.fromMap(Map.of("Linux",
                Map.of("Provider", "pkcs11", "KeyUri", "pkcs11:token=t", "CertificateFile", "/etc/myapp/tls.crt"))).getLinux();
        assertEquals(List.of("pkcs11", "pkcs11:token=t", "/etc/myapp/tls.crt"), List.of(linux.getProvider(), linux.getKeyUri(), linux.getCertificateFile()));

        var file = new LinkedHashMap<String, Object>();
        file.put("path", "/etc/myapp/tls.pem");
        file.put("format", "Pem");
        file.put("key_path", "/etc/myapp/tls.key");
        file.put("password-secret-name", "tls-key-password");
        file.put("AllowUnprotectedPrivateKey", "true");
        var options = CertificateOptions.fromMap(Map.of("RequirePrivateKey", false, "File", file));
        assertFalse(options.isRequirePrivateKey());
        var f = options.getFile();
        assertEquals(List.of(CertificateFileFormat.PEM, "/etc/myapp/tls.pem", "/etc/myapp/tls.key", "tls-key-password", true),
                List.of(f.getFormat(), f.getPath(), f.getKeyPath(), f.getPasswordSecretName(), f.isAllowUnprotectedPrivateKey()));
    }

    @Test
    void aConfigurationSection_WithATypo_OrAWrongValue_IsRefused() {
        var unknown = assertThrows(IllegalArgumentException.class, () -> CertificateOptions.fromMap(Map.of("Windws", Map.of())));
        assertTrue(unknown.getMessage().startsWith("settings has an unknown key 'Windws'"), unknown.getMessage());

        var location = assertThrows(IllegalArgumentException.class, () -> CertificateOptions.fromMap(Map.of("Windows", Map.of("StoreLocation", "Everywhere"))));
        assertEquals("settings.windows.storeLocation must be one of CURRENT_USER, LOCAL_MACHINE; it is 'Everywhere'.", location.getMessage());

        assertThrows(IllegalArgumentException.class, () -> CertificateOptions.fromMap(Map.of("File", "tls.pfx")));
        assertThrows(IllegalArgumentException.class, () -> CertificateOptions.fromMap(Map.of("RequirePrivateKey", "yes")));
        assertThrows(IllegalArgumentException.class, () -> CertificateOptions.fromMap(Map.of("requirePrivateKey", true, "require_private_key", false)));
        assertThrows(NullPointerException.class, () -> CertificateOptions.fromMap(null));
    }

    @Test
    void theDefaults_AreTheSafeOnes() {
        var options = new CertificateOptions();
        var store = new CertificateStoreOptions();
        var linux = new LinuxOpenSslProviderOptions();
        var file = new CertificateFileOptions();

        assertTrue(options.isRequirePrivateKey());
        assertEquals(List.of(StoreLocation.LOCAL_MACHINE, StoreName.MY), List.of(store.getStoreLocation(), store.getStoreName()));
        assertEquals("tpm2", linux.getProvider());
        assertEquals(CertificateFileFormat.PKCS12, file.getFormat());
        assertFalse(file.isAllowUnprotectedPrivateKey());
    }
}
