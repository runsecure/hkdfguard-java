package io.github.runsecure.hkdfguard.cache.hashicorpvault;

/** The version of a KV secrets engine, which decides its read path and response shape. */
public enum VaultKvVersion {
    /** KV version 1: one unversioned value per path, read at {mount}/{path}. */
    V1,

    /** KV version 2: versioned secrets, read at {mount}/data/{path}; the latest version is read. */
    V2
}
