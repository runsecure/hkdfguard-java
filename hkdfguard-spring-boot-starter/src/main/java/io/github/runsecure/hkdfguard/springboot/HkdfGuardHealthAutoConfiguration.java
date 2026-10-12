package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;

/**
 * Adds {@link HkdfGuardHealthIndicator}, reported as {@code hkdfguard} by Actuator's health
 * endpoint, when the application has Actuator and a key ring. Turn it off with
 * {@code management.health.hkdfguard.enabled=false}.
 */
@AutoConfiguration(after = HkdfGuardAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
@ConditionalOnBean(KeyRing.class)
public class HkdfGuardHealthAutoConfiguration {
    /** Created by Spring; applications don't construct it. */
    public HkdfGuardHealthAutoConfiguration() {
    }

    /**
     * @param keyRing the application's key ring
     * @return the indicator, contributed under the name {@code hkdfguard}
     */
    // On the method, not the class: a class-level condition from spring-boot-health would be loaded
    // before @ConditionalOnClass could rule it out, failing startup in an application without it.
    @Bean
    @ConditionalOnMissingBean(name = "hkdfguardHealthIndicator")
    @ConditionalOnEnabledHealthIndicator("hkdfguard")
    public HkdfGuardHealthIndicator hkdfguardHealthIndicator(KeyRing keyRing) {
        return new HkdfGuardHealthIndicator(keyRing);
    }
}
