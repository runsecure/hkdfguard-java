/**
 * The shared base of the secret stores' pipeline writers,
 * {@link io.github.runsecure.hkdfguard.pipeline.SecretPipelineWriterBase}: it pulls a fixed list of
 * secrets, encrypts each at once with a pipeline data protector bound to its file name, and writes
 * one file per secret - the folder layout the file-per-secret cache reads at runtime. No key ring
 * is involved.
 */
module io.github.runsecure.hkdfguard.pipeline {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires transitive io.github.runsecure.hkdfguard.cache;
    requires io.github.runsecure.hkdfguard.cache.filepersecret;
    requires io.github.runsecure.hkdfguard.remote;

    exports io.github.runsecure.hkdfguard.pipeline;
}
