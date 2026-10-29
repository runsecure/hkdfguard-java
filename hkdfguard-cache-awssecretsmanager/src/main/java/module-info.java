/**
 * A protected read-only cache over AWS Secrets Manager, read through the AWS SDK for Java 2.x's
 * {@code SecretsManagerAsyncClient}, which the application builds, configures and closes. Each
 * secret is taken out of the HTTP response body before the SDK can turn it into a String.
 */
module io.github.runsecure.hkdfguard.cache.awssecretsmanager {
    requires transitive io.github.runsecure.hkdfguard.cache;
    requires transitive software.amazon.awssdk.services.secretsmanager;
    requires software.amazon.awssdk.core;
    requires software.amazon.awssdk.awscore;
    requires software.amazon.awssdk.http;
    requires org.reactivestreams;

    exports io.github.runsecure.hkdfguard.cache.awssecretsmanager;
}
