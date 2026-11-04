/**
 * A provisioning pipeline's writer over AWS Secrets Manager,
 * {@link io.github.runsecure.hkdfguard.pipeline.awssecretsmanager.AwsSecretsManagerSecretPipelineWriterImpl},
 * read through the AWS SDK for Java 2.x's {@code SecretsManagerAsyncClient}, which the application
 * builds, configures and closes. Each secret is taken out of the HTTP response body and encrypted
 * before the SDK can turn it into a String.
 */
module io.github.runsecure.hkdfguard.pipeline.awssecretsmanager {
    requires transitive io.github.runsecure.hkdfguard.pipeline;
    requires transitive software.amazon.awssdk.services.secretsmanager;
    requires software.amazon.awssdk.core;
    requires software.amazon.awssdk.awscore;
    requires software.amazon.awssdk.http;
    requires org.reactivestreams;
    requires io.github.runsecure.hkdfguard.remote;

    exports io.github.runsecure.hkdfguard.pipeline.awssecretsmanager;
}
