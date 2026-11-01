package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Adds a {@link ProtectedEnvironment} over the application's {@code Environment} whenever there is
 * a {@link KeyRing} - the one {@link HkdfGuardAutoConfiguration} builds, or the application's own,
 * of any type. Values are parsed with the application's {@link EncryptedFormatProvider} bean if it
 * declares one, and the default format otherwise; the built ring uses its own.
 */
@AutoConfiguration(after = HkdfGuardAutoConfiguration.class)
@ConditionalOnBean(KeyRing.class)
public class HkdfGuardEncryptedConfigurationAutoConfiguration {
    /** Created by Spring; applications don't construct it. */
    public HkdfGuardEncryptedConfigurationAutoConfiguration() {
    }

    /**
     * @param environment    the application's configuration
     * @param keyRing        the ring the protected values were encrypted under
     * @param formatProvider the application's format, if it declares one
     * @return protected access to every property source in the environment
     */
    @Bean
    @ConditionalOnMissingBean
    public ProtectedEnvironment protectedEnvironment(Environment environment, KeyRing keyRing,
                                                     ObjectProvider<EncryptedFormatProvider> formatProvider) {
        return new ProtectedEnvironment(environment, keyRing, formatProvider.getIfAvailable(DefaultFormatProviderImpl::new));
    }
}
