package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Adds a {@link ProtectedEnvironment} over the application's {@code Environment} whenever there is
 * a {@link KeyRingImpl} - the one {@link HkdfGuardAutoConfiguration} builds, or the application's
 * own.
 */
@AutoConfiguration(after = HkdfGuardAutoConfiguration.class)
@ConditionalOnBean(KeyRingImpl.class)
public class HkdfGuardEncryptedConfigurationAutoConfiguration {
    /** Created by Spring; applications don't construct it. */
    public HkdfGuardEncryptedConfigurationAutoConfiguration() {
    }

    /**
     * @param environment the application's configuration
     * @param keyRing     the ring the protected values were encrypted under
     * @return protected access to every property source in the environment
     */
    @Bean
    @ConditionalOnMissingBean
    public ProtectedEnvironment protectedEnvironment(Environment environment, KeyRingImpl keyRing) {
        return new ProtectedEnvironment(environment, keyRing);
    }
}
