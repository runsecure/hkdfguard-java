package io.github.runsecure.hkdfguard.springboot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.springboot.TestKeyWrappers.TestKekWrapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.SystemEnvironmentPropertySource;
import org.springframework.core.io.FileSystemResource;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

/**
 * End to end, from a deployment pipeline encrypting configuration to a Spring Boot application
 * decrypting it, with real files in between:
 * <ol>
 * <li>Pipeline: random secrets are encrypted with {@link AesGcmPipelineDataProtectorImpl}, each
 * bound to its own canonical property name, and written into a nested {@code application.yml}
 * alongside plain settings and the {@code hkdfguard.*} settings themselves. The pipeline's key is
 * then wrapped under the deployment's KEK ({@link TestKekWrapper}, standing in for the native
 * wrapper) into a key file.</li>
 * <li>Runtime: Spring loads the YAML, the starter builds the ring from the key file, and the
 * {@link ProtectedEnvironment} bean decrypts every value by its property name.</li>
 * </ol>
 * Secrets are random per seed; the seeded tests are reproducible, and the random-seed test prints
 * its seed so any failure can be replayed.
 */
class YamlConfigurationEndToEndTest {
    private static final int KEY_VERSION = 1;

    private static final Map<String, String> PLAIN_SETTINGS = Map.of(
            "app.greeting", "Hello",
            "app.limits.max-users", "250",
            "server.port", "8443");

    // Whole graphemes, never split surrogates: ASCII, YAML-significant characters, whitespace,
    // accented and CJK text, and emoji (surrogate pairs in UTF-16, 4 bytes in UTF-8).
    private static final List<String> GRAPHEMES = new ArrayList<>();

    static {
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().forEach(c -> GRAPHEMES.add(String.valueOf((char) c)));
        GRAPHEMES.addAll(List.of("\"", "\\", "/", "{", "}", "[", "]", ":", ",", "=", ";", "'", "<", ">", "&", "%", "+", " ", "#", "-", "?",
                "\n", "\t", "é", "ü", "ß", "ñ", "Ω", "中", "文", "✓", "€", "🔐", "🚀"));
    }

    @TempDir
    Path directory;

    /** A deployment: its configuration file, its wrapped key file, and the secrets it holds. */
    record Deployment(Path configuration, Path keyFile, Map<String, String> secrets) {
        Deployment withKeyFile(Path other) {
            return new Deployment(configuration, other, secrets);
        }
    }

    // --- Tests ---------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(ints = {1, 42, 20260601})
    void everySecretEncryptedByThePipeline_DecryptsAtRuntime(int seed) {
        assertEverySecretRoundTrips(seed);
    }

    @Test
    void everySecretEncryptedByThePipeline_DecryptsAtRuntime_RandomSeed() {
        var seed = new Random().nextInt();
        System.out.println("Seed: " + seed + " (replay with everySecretEncryptedByThePipeline_DecryptsAtRuntime(" + seed + "))");

        assertEverySecretRoundTrips(seed);
    }

    @Test
    void theConfigurationFile_HoldsOnlyCiphertextForSecrets() throws IOException {
        var kek = new TestKekWrapper();
        var deployment = runPipeline(7, kek);
        var yaml = Files.readString(deployment.configuration());

        start(deployment, kek, context -> {
            for (var entry : deployment.secrets().entrySet()) {
                assertThat(context.getEnvironment().getProperty(entry.getKey())).startsWith("enc::v" + KEY_VERSION + "::");
                if (entry.getValue().length() >= 12)
                    assertThat(yaml).doesNotContain(entry.getValue());
            }
        });
    }

    @Test
    void plainSettings_PassThroughUnchanged() {
        var kek = new TestKekWrapper();
        var deployment = runPipeline(7, kek);

        start(deployment, kek, context -> PLAIN_SETTINGS.forEach((name, value) -> assertThat(context.getEnvironment().getProperty(name)).isEqualTo(value)));
    }

    @Test
    void aSecretOverriddenByAnEnvironmentVariable_DecryptsByThePropertyName() {
        var kek = new TestKekWrapper();
        try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), KEY_VERSION)) {
            var deployment = writeDeployment(protector, kek, Map.of("connection-strings.admin", "from-the-file"));
            // The same pipeline run encrypts the override, so it is under the deployment's key and
            // bound to the property name - Spring maps CONNECTION_STRINGS_ADMIN to that name.
            var variable = protector.encrypt("from-the-environment", "connection-strings.admin");

            runner(deployment, kek)
                    .withInitializer(context -> context.getEnvironment().getPropertySources().addFirst(
                            new SystemEnvironmentPropertySource("variables", Map.of("CONNECTION_STRINGS_ADMIN", variable))))
                    .run(context -> assertThat(decryptChars(context, "connection-strings.admin")).isEqualTo("from-the-environment"));
        }
    }

    @Test
    void aSecretMovedToAnotherKeyInTheFile_FailsAuthentication() {
        var kek = new TestKekWrapper();
        var deployment = runPipeline(7, kek);
        var names = new ArrayList<>(deployment.secrets().keySet());
        var first = names.getFirst();
        var second = names.getLast();

        // An attacker with write access to the file but no key swaps two encrypted values.
        rewriteYaml(deployment.configuration(), yaml -> {
            var firstValue = getValue(yaml, first);
            setValue(yaml, first, getValue(yaml, second));
            setValue(yaml, second, firstValue);
        });

        start(deployment, kek, context -> {
            var environment = context.getBean(ProtectedEnvironment.class);
            assertThatThrownBy(() -> environment.decrypt(first, new char[8192])).isInstanceOf(AuthenticationTagMismatchException.class);
            assertThatThrownBy(() -> environment.decrypt(second, new char[8192])).isInstanceOf(AuthenticationTagMismatchException.class);
        });
    }

    @Test
    void aTamperedCiphertextInTheFile_FailsAuthentication() {
        var kek = new TestKekWrapper();
        var deployment = runPipeline(7, kek);
        var target = deployment.secrets().keySet().iterator().next();

        rewriteYaml(deployment.configuration(), yaml -> {
            var value = getValue(yaml, target);
            var flipped = value.charAt(value.length() - 4) == 'A' ? 'B' : 'A';
            setValue(yaml, target, value.substring(0, value.length() - 4) + flipped + value.substring(value.length() - 3));
        });

        start(deployment, kek, context -> assertThatThrownBy(() -> context.getBean(ProtectedEnvironment.class).decrypt(target, new char[8192]))
                .isInstanceOf(CryptographicException.class));
    }

    @Test
    void theKeyFile_UnwrapsOnlyUnderTheDeploymentsKek() {
        var deployment = runPipeline(7, new TestKekWrapper());

        runner(deployment, new TestKekWrapper()).run(context -> assertThat(context.getStartupFailure())
                .hasStackTraceContaining("The wrapped key did not unwrap under this KEK."));
    }

    @Test
    void aNewDeploymentsKey_CannotReadThePreviousDeploymentsConfiguration() {
        var kek = new TestKekWrapper();
        var previous = runPipeline(7, kek);
        var current = runPipeline(7, kek);

        // Same secrets and the same version number, but each pipeline run generated its own key.
        start(previous.withKeyFile(current.keyFile()), kek, context -> {
            var name = previous.secrets().keySet().iterator().next();
            assertThatThrownBy(() -> context.getBean(ProtectedEnvironment.class).decrypt(name, new char[8192]))
                    .isInstanceOf(AuthenticationTagMismatchException.class);
        });
    }

    @Test
    void aMissingSecret_DecryptsToNothing_RatherThanThrowing() {
        var kek = new TestKekWrapper();
        var deployment = runPipeline(7, kek);

        start(deployment, kek, context -> {
            var environment = context.getBean(ProtectedEnvironment.class);
            assertThat(environment.decrypt("does.not.exist", new char[16])).isZero();
            assertThat(environment.findMaxDecryptedLength("does.not.exist")).isEmpty();
        });
    }

    @Test
    void aPipelineSecretTooLargeForTheFormat_IsRefusedAtEncryptTime() {
        try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), KEY_VERSION)) {
            // ~4 KB of plaintext can't fit in a 4096-character formatted value.
            assertThatThrownBy(() -> protector.encrypt("x".repeat(4000), "certificates.too-large")).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void withoutAKeyRing_ThereIsNoProtectedEnvironment() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, HkdfGuardAutoConfiguration.class,
                        HkdfGuardEncryptedConfigurationAutoConfiguration.class))
                .withClassLoader(new FilteredClassLoader("io.github.runsecure.hkdfguard.keywrapping"))
                .run(context -> assertThat(context).doesNotHaveBean(ProtectedEnvironment.class));
    }

    @Test
    void anApplicationsOwnProtectedEnvironment_ReplacesTheDefault() {
        var kek = new TestKekWrapper();
        var deployment = runPipeline(7, kek);
        var own = new ProtectedEnvironment(new org.springframework.core.env.StandardEnvironment(), TestKeyWrappers.ring());

        runner(deployment, kek).withBean(ProtectedEnvironment.class, () -> own)
                .run(context -> assertThat(context.getBean(ProtectedEnvironment.class)).isSameAs(own));
    }

    // --- The two stages --------------------------------------------------------------------------

    /**
     * The deployment pipeline: encrypt every secret under one fresh key, each bound to its own
     * property name; write the YAML; wrap the key under the KEK into a key file.
     */
    private Deployment runPipeline(int seed, KeyWrapper kek) {
        try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), KEY_VERSION)) {
            return writeDeployment(protector, kek, generateSecrets(new Random(seed)));
        }
    }

    private Deployment writeDeployment(AesGcmPipelineDataProtectorImpl protector, KeyWrapper kek, Map<String, String> secrets) {
        try {
            var run = UUID.randomUUID().toString().replace("-", "");
            var configuration = directory.resolve("application." + run + ".yml");
            var keyFile = directory.resolve("dek." + run + ".bin");

            // Hand the key to the wrap step, as the pipeline does with the native platform's wrapper.
            var dek = Base64.getDecoder().decode(protector.getKeyAsBase64().toString());
            var wrapped = new byte[256];
            try {
                var wrappedLength = kek.wrapAsync(dek, wrapped).join();
                Files.write(keyFile, Arrays.copyOf(wrapped, wrappedLength));
            } finally {
                ArrayUtility.zeroMemory(dek);
            }

            var yaml = new LinkedHashMap<String, Object>();
            PLAIN_SETTINGS.forEach((name, value) -> setValue(yaml, name, value));
            setValue(yaml, "hkdfguard.service-name", "com.example.orders");
            setValue(yaml, "hkdfguard.key-refresh-interval", "60");
            setValue(yaml, "hkdfguard.key-files[0].version", String.valueOf(KEY_VERSION));
            setValue(yaml, "hkdfguard.key-files[0].path", keyFile.toString());
            secrets.forEach((name, secret) -> setValue(yaml, name, protector.encrypt(secret, name)));
            writeYaml(configuration, yaml);

            return new Deployment(configuration, keyFile, secrets);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The application: Spring loads the YAML and the starter builds the ring from it. */
    private static ApplicationContextRunner runner(Deployment deployment, KeyWrapper kek) {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, HkdfGuardAutoConfiguration.class,
                        HkdfGuardEncryptedConfigurationAutoConfiguration.class))
                .withBean(KeyWrapper.class, () -> kek)
                // Which key file the application reads, as a deployment's own settings would say. Spring
                // takes a list from one property source, so the entry is given whole.
                .withPropertyValues("hkdfguard.key-files[0].version=" + KEY_VERSION, "hkdfguard.key-files[0].path=" + deployment.keyFile())
                .withInitializer(context -> {
                    try {
                        for (var source : new YamlPropertySourceLoader().load("application.yml", new FileSystemResource(deployment.configuration())))
                            context.getEnvironment().getPropertySources().addLast(source);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                });
    }

    private static void start(Deployment deployment, KeyWrapper kek, Consumer<AssertableApplicationContext> check) {
        runner(deployment, kek).run(context -> {
            assertThat(context).hasNotFailed();
            check.accept(context);
        });
    }

    private void assertEverySecretRoundTrips(int seed) {
        var kek = new TestKekWrapper();
        var deployment = runPipeline(seed, kek);

        start(deployment, kek, context -> {
            var environment = context.getBean(ProtectedEnvironment.class);
            assertThat(deployment.secrets()).isNotEmpty();
            deployment.secrets().forEach((name, secret) -> {
                var maxLength = environment.findMaxDecryptedLength(name);
                assertThat(maxLength).as("seed %d: %s not found", seed, name).isPresent();

                var chars = new char[maxLength.getAsInt()];
                var charsWritten = environment.decrypt(name, chars);
                assertThat(new String(chars, 0, charsWritten)).as("seed %d: chars at %s", seed, name).isEqualTo(secret);

                var bytes = new byte[maxLength.getAsInt()];
                var bytesWritten = environment.decrypt(name, bytes);
                assertThat(Arrays.copyOf(bytes, bytesWritten)).as("seed %d: bytes at %s", seed, name).isEqualTo(secret.getBytes(StandardCharsets.UTF_8));
            });
        });
    }

    private static String decryptChars(AssertableApplicationContext context, String name) {
        var chars = new char[8192];
        var written = context.getBean(ProtectedEnvironment.class).decrypt(name, chars);
        return new String(chars, 0, written);
    }

    // --- Secret generation -----------------------------------------------------------------------

    /**
     * Random secrets at realistic property names, all in Spring's canonical form: top-level
     * sections, nested sub-sections, and a list (a YAML sequence, read as {@code keys[0]},
     * {@code keys[1]}, ...). Section and leaf names come from separate namespaces so no name is
     * both a value and a section.
     */
    private static Map<String, String> generateSecrets(Random random) {
        var secrets = new LinkedHashMap<String, String>();

        var sectionCount = 2 + random.nextInt(3);
        for (var s = 0; s < sectionCount; s++) {
            var section = "section" + s + "-" + randomName(random);
            for (var l = 1 + random.nextInt(4); l > 0; l--)
                secrets.put(section + ".value" + l + "-" + randomName(random), randomSecret(random, 1 + random.nextInt(119)));

            var sub = section + ".sub-" + randomName(random);
            for (var l = 1 + random.nextInt(3); l > 0; l--)
                secrets.put(sub + ".value" + l + "-" + randomName(random), randomSecret(random, 1 + random.nextInt(119)));
        }

        for (var i = 0; i < 2 + random.nextInt(3); i++)
            secrets.put("api-keys.keys[" + i + "]", randomSecret(random, 1 + random.nextInt(119)));

        secrets.put("connection-strings.admin", randomSecret(random, 1 + random.nextInt(119)));
        secrets.put("connection-strings.reporting", randomSecret(random, 1 + random.nextInt(119)));
        // Formatted values are capped at 4096 characters (about 3 KB of UTF-8): 700 graphemes is at
        // most 2,800 bytes even if every one is a 4-byte emoji.
        secrets.put("certificates.long", randomSecret(random, 700));

        return secrets;
    }

    private static String randomName(Random random) {
        var name = new StringBuilder();
        for (var i = 0; i < 6; i++)
            name.append((char) ('a' + random.nextInt(26)));
        return name.toString();
    }

    private static String randomSecret(Random random, int length) {
        var secret = new StringBuilder();
        for (var i = 0; i < length; i++)
            secret.append(GRAPHEMES.get(random.nextInt(GRAPHEMES.size())));
        return secret.toString();
    }

    // --- YAML helpers ----------------------------------------------------------------------------

    private static void writeYaml(Path path, Map<String, Object> yaml) {
        var options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        try {
            Files.writeString(path, new Yaml(options).dump(yaml));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static void rewriteYaml(Path path, Consumer<Map<String, Object>> edit) {
        try {
            var yaml = (Map<String, Object>) new Yaml().load(Files.readString(path));
            edit.accept(yaml);
            writeYaml(path, yaml);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // A property name's segments: "a.b[2].c" is a, b, 2, c - an index segment selects a list item.
    private static List<String> segments(String name) {
        return Arrays.stream(name.replace("[", ".").replace("]", "").split("\\.")).toList();
    }

    // Walks/creates the nested maps (and lists, for index segments) a property name names.
    @SuppressWarnings("unchecked")
    private static void setValue(Map<String, Object> root, String name, String value) {
        var parts = segments(name);
        Object node = root;
        for (var i = 0; i < parts.size(); i++) {
            var last = i == parts.size() - 1;
            var nextIsIndex = !last && parts.get(i + 1).chars().allMatch(Character::isDigit);
            Object created = last ? value : nextIsIndex ? new ArrayList<>() : new LinkedHashMap<String, Object>();

            if (node instanceof List<?> list) {
                var items = (List<Object>) list;
                var index = Integer.parseInt(parts.get(i));
                if (index == items.size())
                    items.add(created);
                else if (last)
                    items.set(index, created);
                node = items.get(index);
            } else {
                var map = (Map<String, Object>) node;
                if (last || !map.containsKey(parts.get(i)))
                    map.put(parts.get(i), created);
                node = map.get(parts.get(i));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static String getValue(Map<String, Object> root, String name) {
        Object node = root;
        for (var part : segments(name))
            node = node instanceof List<?> list ? list.get(Integer.parseInt(part)) : ((Map<String, Object>) node).get(part);
        return (String) node;
    }
}
