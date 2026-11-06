package io.github.runsecure.hkdfguard.integration.hashicorpvault;

/**
 * A model of a request or response body Vault's OpenAPI spec defines: every class in the
 * {@code schema} package. A model is written as a JSON object holding only the members that are
 * set, and read with its static {@code fromJson(JsonValue)}.
 */
public interface VaultModel {
    /** Writes this model as one JSON object. */
    void writeJson(JsonWriter writer);
}
