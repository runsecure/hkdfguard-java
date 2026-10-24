package io.github.runsecure.hkdfguard.options;

import io.github.runsecure.hkdfguard.abstractions.RefreshFailurePolicy;
import io.github.runsecure.hkdfguard.abstractions.ServiceNames;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import java.math.BigInteger;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.regex.Pattern;

/**
 * Plain-data mirror of the settings {@link KeyRingBuilder} itself exposes: the service name, key
 * refresh interval, refresh-failure policy, ephemeral key rotation and retention, key files and
 * ephemeral keys. It carries no behavior: the key wrapper, crypto provider factory and format
 * provider a real ring needs still come from the caller - {@link #applyTo(KeyRingBuilder)} copies
 * this data onto a builder the caller finishes and builds.
 *
 * <p>A JavaBean, so a configuration binder can populate it directly - Spring's
 * {@code @ConfigurationProperties("hkdfguard")}, Jackson, or MicroProfile Config. Without one,
 * {@link #fromMap(Map)} reads a parsed configuration section. Either way, check it with
 * {@link #requireValid()} and then apply it:
 *
 * <pre>{@code
 * var options = HkdfGuardOptions.fromMap(settings).requireValid();
 * try (var ring = options.applyTo(new KeyRingBuilder())
 *         .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl(options.getServiceName()))
 *         .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
 *         .buildAsync().join()) {
 *     ...
 * }
 * }</pre>
 *
 * <p>Not thread-safe: populate it, then share it only once it is no longer changed.
 */
public final class HkdfGuardOptions {
    /**
     * The largest {@link #getEphemeralKeyRotationHours() ephemeral key rotation hours}: the longest
     * rotation interval {@link KeyRingBuilder} accepts, in whole hours.
     */
    public static final int MAX_EPHEMERAL_KEY_ROTATION_HOURS = 1193;

    private static final Pattern INTEGER = Pattern.compile("[+-]?\\d+");
    private static final List<String> FIELDS = List.of("serviceName", "keyRefreshInterval", "maxRefreshFailures", "failOpenOnRefreshFailure",
            "ephemeralKeyRotationHours", "disableEphemeralKeyRotation", "ephemeralKeyRetentionHours", "keyFiles", "ephemeralKeys");
    private static final List<String> KEY_FILE_FIELDS = List.of("version", "path");

    private String serviceName;
    private Integer keyRefreshInterval;
    private Integer maxRefreshFailures;
    private boolean failOpenOnRefreshFailure;
    private Integer ephemeralKeyRotationHours;
    private boolean disableEphemeralKeyRotation;
    private Integer ephemeralKeyRetentionHours;
    private List<KeyFileOptions> keyFiles = new ArrayList<>();
    private List<Integer> ephemeralKeys = new ArrayList<>();

    /** Options with nothing set: applying them leaves every builder default in place. */
    public HkdfGuardOptions() {
    }

    // --- Properties ------------------------------------------------------------------------------

    /** @return the service name identifying this ring's KEK to the native KMS library, or {@code null} */
    public String getServiceName() {
        return serviceName;
    }

    /** @param serviceName the service name identifying this ring's KEK to the native KMS library */
    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    /**
     * How often, in seconds (1-300), each key is re-revealed through the KEK to confirm the KEK is
     * still available. A revocation check, not a limit on how long the DEK stays in memory. Together
     * with {@link #getMaxRefreshFailures()} it sets how quickly a revoked KEK stops a running process
     * - about maxRefreshFailures x keyRefreshInterval.
     *
     * @return the interval in seconds, or {@code null} when unset
     */
    public Integer getKeyRefreshInterval() {
        return keyRefreshInterval;
    }

    /** @param keyRefreshInterval seconds between re-reveals, 1-300; {@code null} for unset */
    public void setKeyRefreshInterval(Integer keyRefreshInterval) {
        this.keyRefreshInterval = keyRefreshInterval;
    }

    /**
     * How many consecutive failed refreshes are tolerated before a key's provider fails closed -
     * zeroing the key and refusing every operation until a refresh succeeds. At least 1.
     *
     * @return the limit, or {@code null} to keep {@link KeyRingBuilder#DEFAULT_MAX_REFRESH_FAILURES}
     */
    public Integer getMaxRefreshFailures() {
        return maxRefreshFailures;
    }

    /** @param maxRefreshFailures 1 to 100; {@code null} keeps the builder's default */
    public void setMaxRefreshFailures(Integer maxRefreshFailures) {
        this.maxRefreshFailures = maxRefreshFailures;
    }

    /**
     * True opts out of failing closed: the last good key stays in use however many refreshes fail,
     * so revoking the KEK never stops a running process. Can't be combined with
     * {@link #getMaxRefreshFailures()}.
     *
     * @return whether the ring fails open
     */
    public boolean isFailOpenOnRefreshFailure() {
        return failOpenOnRefreshFailure;
    }

    /** @param failOpenOnRefreshFailure true to keep serving on the last good key */
    public void setFailOpenOnRefreshFailure(boolean failOpenOnRefreshFailure) {
        this.failOpenOnRefreshFailure = failOpenOnRefreshFailure;
    }

    /**
     * Hours between scheduled ephemeral key rotations, 1 to {@link #MAX_EPHEMERAL_KEY_ROTATION_HOURS}.
     * Applies only with ephemeral keys; can't be combined with
     * {@link #isDisableEphemeralKeyRotation()}.
     *
     * @return the hours, or {@code null} to keep the builder's 24-hour default
     */
    public Integer getEphemeralKeyRotationHours() {
        return ephemeralKeyRotationHours;
    }

    /** @param ephemeralKeyRotationHours 1 to {@link #MAX_EPHEMERAL_KEY_ROTATION_HOURS}; {@code null} keeps the default */
    public void setEphemeralKeyRotationHours(Integer ephemeralKeyRotationHours) {
        this.ephemeralKeyRotationHours = ephemeralKeyRotationHours;
    }

    /** @return true when scheduled rotation is off: the startup ephemeral key stays current until restart */
    public boolean isDisableEphemeralKeyRotation() {
        return disableEphemeralKeyRotation;
    }

    /** @param disableEphemeralKeyRotation true to turn scheduled rotation off */
    public void setDisableEphemeralKeyRotation(boolean disableEphemeralKeyRotation) {
        this.disableEphemeralKeyRotation = disableEphemeralKeyRotation;
    }

    /**
     * Hours a superseded ephemeral key stays registered for decryption after a rotation replaces it.
     * At least 1.
     *
     * @return the hours, or {@code null} to keep the builder's 24-hour default
     */
    public Integer getEphemeralKeyRetentionHours() {
        return ephemeralKeyRetentionHours;
    }

    /** @param ephemeralKeyRetentionHours at least 1; {@code null} keeps the default */
    public void setEphemeralKeyRetentionHours(Integer ephemeralKeyRetentionHours) {
        this.ephemeralKeyRetentionHours = ephemeralKeyRetentionHours;
    }

    /** @return the versions whose wrapped DEK is read from a file on disk; a live, mutable list */
    public List<KeyFileOptions> getKeyFiles() {
        return keyFiles;
    }

    /** @param keyFiles the versions read from key files; copied, and {@code null} reads as empty */
    public void setKeyFiles(List<KeyFileOptions> keyFiles) {
        this.keyFiles = keyFiles == null ? new ArrayList<>() : new ArrayList<>(keyFiles);
    }

    /** @return the versions generated fresh in memory at build and never persisted; a live, mutable list */
    public List<Integer> getEphemeralKeys() {
        return ephemeralKeys;
    }

    /** @param ephemeralKeys the ephemeral versions; copied, and {@code null} reads as empty */
    public void setEphemeralKeys(List<Integer> ephemeralKeys) {
        this.ephemeralKeys = ephemeralKeys == null ? new ArrayList<>() : new ArrayList<>(ephemeralKeys);
    }

    // --- Validation and applying -----------------------------------------------------------------

    /**
     * Checks these options against the constraints {@link KeyRingBuilder} enforces, plus what
     * {@link #applyTo(KeyRingBuilder)} and building need: a valid service name, every key file
     * having a path, versions that don't collide across key files and ephemeral keys, and - unless
     * rotation is disabled - no key file above every ephemeral version, which the first ephemeral
     * key rotation would replace as current - caught here, at configuration time, with a much
     * clearer message than a failure deep inside build.
     *
     * @return every failure, or an empty list if these options are valid
     */
    public List<String> validate() {
        var failures = new ArrayList<String>();

        var serviceNameProblem = ServiceNames.getProblem(serviceName);
        if (serviceNameProblem != null)
            failures.add("serviceName is invalid: " + serviceNameProblem);

        if (keyRefreshInterval != null && (keyRefreshInterval < 1 || keyRefreshInterval > 300))
            failures.add("keyRefreshInterval must be between 1 and 300 seconds.");

        if (maxRefreshFailures != null && (maxRefreshFailures < 1 || maxRefreshFailures > RefreshFailurePolicy.MAX_ALLOWED_REFRESH_FAILURES))
            failures.add("maxRefreshFailures must be between 1 and " + RefreshFailurePolicy.MAX_ALLOWED_REFRESH_FAILURES + ".");

        if (ephemeralKeyRotationHours != null && (ephemeralKeyRotationHours < 1 || ephemeralKeyRotationHours > MAX_EPHEMERAL_KEY_ROTATION_HOURS))
            failures.add("ephemeralKeyRotationHours must be between 1 and " + MAX_EPHEMERAL_KEY_ROTATION_HOURS + ".");

        if (ephemeralKeyRetentionHours != null && ephemeralKeyRetentionHours < 1)
            failures.add("ephemeralKeyRetentionHours must be at least 1.");

        if (disableEphemeralKeyRotation && ephemeralKeyRotationHours != null)
            failures.add("disableEphemeralKeyRotation and ephemeralKeyRotationHours can't both be set: one turns rotation off, the other schedules it.");

        if (failOpenOnRefreshFailure && maxRefreshFailures != null)
            failures.add("failOpenOnRefreshFailure and maxRefreshFailures can't both be set: one fails open, the other fails closed.");

        if (keyFiles.isEmpty() && ephemeralKeys.isEmpty())
            failures.add("At least one key file or ephemeral key is required.");

        // Counted in first-seen order, so the report lists duplicates in the order they appear.
        var versions = new LinkedHashMap<Integer, Integer>();
        for (var i = 0; i < keyFiles.size(); i++) {
            var keyFile = keyFiles.get(i);
            if (keyFile == null) {
                failures.add("keyFiles[" + i + "] is missing.");
                continue;
            }
            if (keyFile.getPath().isBlank())
                failures.add("keyFiles version " + keyFile.getVersion() + " is missing a path.");
            versions.merge(keyFile.getVersion(), 1, Integer::sum);
        }
        for (var i = 0; i < ephemeralKeys.size(); i++) {
            var version = ephemeralKeys.get(i);
            if (version == null)
                failures.add("ephemeralKeys[" + i + "] is missing.");
            else
                versions.merge(version, 1, Integer::sum);
        }
        versions.forEach((version, count) -> {
            if (count > 1)
                failures.add("Version " + version + " is registered more than once across keyFiles/ephemeralKeys.");
        });

        // Rotation adds at the current version + 1, so with a key file above every ephemeral version
        // the first rotation would make an in-memory key current - as KeyRingBuilder refuses at build.
        if (!disableEphemeralKeyRotation) {
            var highestKeyFile = keyFiles.stream().filter(Objects::nonNull).mapToInt(KeyFileOptions::getVersion).max();
            var highestEphemeral = ephemeralKeys.stream().filter(Objects::nonNull).mapToInt(Integer::intValue).max();
            if (highestKeyFile.isPresent() && highestEphemeral.isPresent() && highestKeyFile.getAsInt() > highestEphemeral.getAsInt())
                failures.add("Key file version " + highestKeyFile.getAsInt() + " is above every ephemeral version, so the first scheduled rotation "
                        + "would replace it as the current version and new values would be encrypted under a key that does not survive a restart. "
                        + "Register the ephemeral key at a version above every key file, or set disableEphemeralKeyRotation.");
        }

        return failures;
    }

    /**
     * Throws unless these options are valid.
     *
     * @return these same options, for chaining into {@link #applyTo(KeyRingBuilder)}
     * @throws OptionsValidationException any rule is broken; it lists every failure
     */
    public HkdfGuardOptions requireValid() {
        var failures = validate();
        if (!failures.isEmpty())
            throw new OptionsValidationException(failures);
        return this;
    }

    /**
     * Copies every set option onto {@code builder}; unset ones leave the builder's defaults in place.
     * The caller still supplies the key wrapper, crypto provider factory and (optionally) format
     * provider, and builds - those are behavior, not something options carry as data. Doesn't
     * validate: call {@link #requireValid()} first for one clear report of every problem.
     *
     * @param builder the builder to configure
     * @return {@code builder}, for chaining
     * @throws NullPointerException     {@code builder} is null
     * @throws IllegalArgumentException an option the builder itself rejects
     */
    public KeyRingBuilder applyTo(KeyRingBuilder builder) {
        Objects.requireNonNull(builder, "builder");

        if (serviceName != null)
            builder.withServiceName(serviceName);

        if (keyRefreshInterval != null)
            builder.withKeyRefreshInterval(keyRefreshInterval);

        if (maxRefreshFailures != null)
            builder.withMaxRefreshFailures(maxRefreshFailures);

        if (failOpenOnRefreshFailure)
            builder.withFailOpenOnRefreshFailure();

        if (ephemeralKeyRotationHours != null)
            builder.withEphemeralKeyRotation(Duration.ofHours(ephemeralKeyRotationHours));

        if (disableEphemeralKeyRotation)
            builder.withoutEphemeralKeyRotation();

        if (ephemeralKeyRetentionHours != null)
            builder.withEphemeralKeyRetention(Duration.ofHours(ephemeralKeyRetentionHours));

        for (var keyFile : keyFiles)
            builder.withKeyFile(keyFile.getVersion(), keyFile.getPath());

        for (var version : ephemeralKeys)
            builder.withEphemeralKey(version);

        return builder;
    }

    // --- Reading configuration -------------------------------------------------------------------

    /**
     * Reads options from a parsed configuration section - a {@code Map} from JSON, YAML or TOML.
     *
     * <p>Keys match a property ignoring case, underscores and hyphens, so a .NET
     * {@code appsettings.json} section ({@code "ServiceName"}, {@code "KeyFiles": [{"Version": 1,
     * "Path": "..."}]}), camelCase, snake_case and Spring's kebab-case ({@code "service-name"}) all
     * read. Integers and booleans may also be strings, as properties files and environment variables
     * supply them. A {@code null} value leaves its property unset. The result is not validated: call
     * {@link #requireValid()} or {@link #validate()}.
     *
     * @param settings the configuration section
     * @return the options it describes
     * @throws NullPointerException     {@code settings} is null
     * @throws IllegalArgumentException an unknown key (a likely typo, never silently ignored), a key
     *                                  given twice, or a value of the wrong type; the message names
     *                                  where
     */
    public static HkdfGuardOptions fromMap(Map<String, ?> settings) {
        Objects.requireNonNull(settings, "settings");
        var reader = new Reader(settings, "settings", FIELDS);
        var options = new HkdfGuardOptions();
        options.serviceName = reader.read("serviceName", HkdfGuardOptions::string);
        options.keyRefreshInterval = reader.read("keyRefreshInterval", HkdfGuardOptions::integer);
        options.maxRefreshFailures = reader.read("maxRefreshFailures", HkdfGuardOptions::integer);
        options.failOpenOnRefreshFailure = Boolean.TRUE.equals(reader.read("failOpenOnRefreshFailure", HkdfGuardOptions::bool));
        options.ephemeralKeyRotationHours = reader.read("ephemeralKeyRotationHours", HkdfGuardOptions::integer);
        options.disableEphemeralKeyRotation = Boolean.TRUE.equals(reader.read("disableEphemeralKeyRotation", HkdfGuardOptions::bool));
        options.ephemeralKeyRetentionHours = reader.read("ephemeralKeyRetentionHours", HkdfGuardOptions::integer);
        options.setKeyFiles(reader.read("keyFiles", listOf(HkdfGuardOptions::keyFile)));
        options.setEphemeralKeys(reader.read("ephemeralKeys", listOf(HkdfGuardOptions::integer)));
        return options;
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

    private static Integer integer(Object value, String where) {
        var number = switch (value) {
            case Integer i -> BigInteger.valueOf(i);
            case Long l -> BigInteger.valueOf(l);
            case Short s -> BigInteger.valueOf(s);
            case Byte b -> BigInteger.valueOf(b);
            case BigInteger big -> big;
            case String text when INTEGER.matcher(text.strip()).matches() -> new BigInteger(text.strip());
            default -> throw new IllegalArgumentException(where + " must be an integer; it is " + describe(value) + ".");
        };
        try {
            return number.intValueExact();
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(where + " is out of range for an integer; it is " + number + ".", e);
        }
    }

    private static Boolean bool(Object value, String where) {
        if (value instanceof Boolean flag)
            return flag;
        if (value instanceof String text && (text.strip().equalsIgnoreCase("true") || text.strip().equalsIgnoreCase("false")))
            return text.strip().equalsIgnoreCase("true");
        throw new IllegalArgumentException(where + " must be true or false; it is " + describe(value) + ".");
    }

    private static String path(Object value, String where) {
        return switch (value) {
            case String text -> text;
            case Path path -> path.toString();
            default -> throw new IllegalArgumentException(where + " must be a path; it is " + typeName(value) + ".");
        };
    }

    private static KeyFileOptions keyFile(Object value, String where) {
        if (value instanceof KeyFileOptions keyFile)
            return keyFile;
        var reader = new Reader(value, where, KEY_FILE_FIELDS);
        var version = reader.read("version", HkdfGuardOptions::integer);
        if (version == null)
            throw new IllegalArgumentException(where + " is missing its version.");
        return new KeyFileOptions(version, reader.read("path", HkdfGuardOptions::path));
    }

    private static <T> BiFunction<Object, String, List<T>> listOf(BiFunction<Object, String, T> convert) {
        return (value, where) -> {
            if (!(value instanceof List<?> list))
                throw new IllegalArgumentException(where + " must be a list; it is " + typeName(value) + ".");
            var result = new ArrayList<T>(list.size());
            for (var i = 0; i < list.size(); i++) {
                var item = list.get(i);
                if (item == null)
                    throw new IllegalArgumentException(where + "[" + i + "] is missing.");
                result.add(convert.apply(item, where + "[" + i + "]"));
            }
            return result;
        };
    }

    private static String typeName(Object value) {
        return value == null ? "null" : value.getClass().getSimpleName();
    }

    private static String describe(Object value) {
        return value instanceof String text ? "'" + text + "'" : value + " (" + typeName(value) + ")";
    }

    // --- Object --------------------------------------------------------------------------------

    @Override
    public boolean equals(Object other) {
        return other instanceof HkdfGuardOptions that
                && Objects.equals(serviceName, that.serviceName)
                && Objects.equals(keyRefreshInterval, that.keyRefreshInterval)
                && Objects.equals(maxRefreshFailures, that.maxRefreshFailures)
                && failOpenOnRefreshFailure == that.failOpenOnRefreshFailure
                && Objects.equals(ephemeralKeyRotationHours, that.ephemeralKeyRotationHours)
                && disableEphemeralKeyRotation == that.disableEphemeralKeyRotation
                && Objects.equals(ephemeralKeyRetentionHours, that.ephemeralKeyRetentionHours)
                && keyFiles.equals(that.keyFiles)
                && ephemeralKeys.equals(that.ephemeralKeys);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serviceName, keyRefreshInterval, maxRefreshFailures, failOpenOnRefreshFailure, ephemeralKeyRotationHours,
                disableEphemeralKeyRotation, ephemeralKeyRetentionHours, keyFiles, ephemeralKeys);
    }

    @Override
    public String toString() {
        return "HkdfGuardOptions[serviceName=" + serviceName + ", keyRefreshInterval=" + keyRefreshInterval + ", maxRefreshFailures=" + maxRefreshFailures
                + ", failOpenOnRefreshFailure=" + failOpenOnRefreshFailure + ", ephemeralKeyRotationHours=" + ephemeralKeyRotationHours
                + ", disableEphemeralKeyRotation=" + disableEphemeralKeyRotation + ", ephemeralKeyRetentionHours=" + ephemeralKeyRetentionHours
                + ", keyFiles=" + keyFiles + ", ephemeralKeys=" + ephemeralKeys + "]";
    }
}
