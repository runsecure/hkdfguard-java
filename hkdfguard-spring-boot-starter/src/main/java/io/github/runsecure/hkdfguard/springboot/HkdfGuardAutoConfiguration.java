package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.options.HkdfGuardOptions;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.CompletionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

/**
 * Builds the application's key ring from {@code hkdfguard.*} properties - the Spring Boot
 * counterpart of the .NET {@code AddKeyRingAsync} registration.
 *
 * <ul>
 * <li>{@link HkdfGuardOptions} is bound from {@code hkdfguard.*}. An unknown property under that
 * prefix fails startup, so a misspelt setting never silently falls back to a default.</li>
 * <li>The ring is built only when {@code hkdfguard.service-name} is set, after
 * {@link HkdfGuardOptions#requireValid()} - every configuration problem is reported at startup, at
 * once. The context closes the ring at shutdown.</li>
 * <li>The key wrapper is the native {@code NativeHkdfKeyWrapperV1Impl} for the configured service
 * when hkdfguard-keywrapping-v1 is available (Java 25, run with
 * {@code --enable-native-access=ALL-UNNAMED}); the crypto provider factory is AES-256-GCM; the
 * format provider is the ring's default.</li>
 * </ul>
 *
 * <p>Declaring a bean of any of these types - {@link HkdfGuardOptions}, {@link KeyWrapper},
 * {@link CryptoProviderFactory}, {@link KeyRing}, or an {@link EncryptedFormatProvider} - replaces or
 * supplies that part.
 */
@AutoConfiguration
@ConditionalOnClass(KeyRingBuilder.class)
public class HkdfGuardAutoConfiguration {
    /** The property prefix the options bind from. */
    public static final String PREFIX = "hkdfguard";

    static final String NATIVE_KEY_WRAPPER_CLASS = "io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl";

    /** Created by Spring; applications don't construct it. */
    public HkdfGuardAutoConfiguration() {
    }

    /**
     * @return options for Spring to bind {@code hkdfguard.*} onto; unknown properties are rejected
     */
    @Bean
    @ConditionalOnMissingBean
    @ConfigurationProperties(prefix = PREFIX, ignoreUnknownFields = false)
    public HkdfGuardOptions hkdfGuardOptions() {
        return new HkdfGuardOptions();
    }

    /** @return AES-256-GCM, the provider every HkdfGuard port uses */
    @Bean
    @ConditionalOnMissingBean
    public CryptoProviderFactory hkdfGuardCryptoProviderFactory() {
        return new AesGcmCryptoProviderFactoryImpl();
    }

    /**
     * The native KMS wrapper for {@code hkdfguard.service-name}. Created by name: this starter
     * targets Java 21 and the native wrapper needs Java 25, so on an older runtime (or without
     * hkdfguard-keywrapping-v1) its class doesn't load and this bean is skipped.
     *
     * @param options the bound options, naming the service
     * @param context supplies the application's class loader
     * @return the native wrapper
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = NATIVE_KEY_WRAPPER_CLASS)
    @ConditionalOnProperty(prefix = PREFIX, name = "service-name")
    public KeyWrapper hkdfGuardKeyWrapper(HkdfGuardOptions options, ApplicationContext context) {
        try {
            var type = Class.forName(NATIVE_KEY_WRAPPER_CLASS, true, context.getClassLoader()).asSubclass(KeyWrapper.class);
            return type.getConstructor(String.class).newInstance(options.getServiceName());
        } catch (InvocationTargetException e) {
            // The constructor's own failure - a bad name, or a native library that's missing or
            // fails verification - is the one worth reporting.
            if (e.getCause() instanceof RuntimeException cause)
                throw cause;
            throw new IllegalStateException("The native key wrapper could not be created.", e.getCause());
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("The native key wrapper could not be created.", e);
        }
    }

    /**
     * Validates the options and builds the ring from them. Building reveals every key file's key
     * through the key wrapper, so a KEK that is missing or refused fails startup rather than the
     * first decrypt.
     *
     * @param options         the bound options
     * @param keyWrapper      the key wrapper, native unless the application declares its own
     * @param factory         the crypto provider factory
     * @param formatProvider  a format provider, if the application declares one
     * @return the built ring, closed with the context
     * @throws io.github.runsecure.hkdfguard.options.OptionsValidationException the options are
     *                                                                          invalid; it lists every
     *                                                                          problem
     * @throws IllegalStateException no key wrapper is available, or building failed
     */
    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean(KeyRing.class)
    @ConditionalOnProperty(prefix = PREFIX, name = "service-name")
    public KeyRingImpl hkdfGuardKeyRing(HkdfGuardOptions options, ObjectProvider<KeyWrapper> keyWrapper, CryptoProviderFactory factory,
                                        ObjectProvider<EncryptedFormatProvider> formatProvider) {
        options.requireValid();

        var wrapper = keyWrapper.getIfAvailable();
        if (wrapper == null)
            throw new IllegalStateException("hkdfguard.service-name is set, but there is no KeyWrapper. Add hkdfguard-keywrapping-v1 and run on Java 25 "
                    + "with --enable-native-access=ALL-UNNAMED, or declare a KeyWrapper bean.");

        var builder = options.applyTo(new KeyRingBuilder()).withKeyWrapper(wrapper).withCryptoProviderFactory(factory);
        formatProvider.ifAvailable(builder::withFormatProvider);
        try {
            return builder.buildAsync().join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof RuntimeException cause)
                throw cause;
            throw new IllegalStateException("The HkdfGuard key ring could not be built: " + e.getCause().getMessage(), e.getCause());
        }
    }
}
