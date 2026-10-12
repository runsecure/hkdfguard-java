package io.github.runsecure.hkdfguard.options;

import java.util.Objects;

/**
 * One {@link io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder#withKeyFile(int, String)}
 * registration: a version paired with the path to its wrapped DEK file on disk. A JavaBean, so
 * configuration binders (Spring's {@code @ConfigurationProperties}, Jackson, MicroProfile Config)
 * can populate it.
 */
public final class KeyFileOptions {
    private int version;
    private String path = "";

    /** An empty registration, for binders to populate. */
    public KeyFileOptions() {
    }

    /**
     * @param version the key version the file holds
     * @param path    the wrapped DEK file; {@code null} reads as empty
     */
    public KeyFileOptions(int version, String path) {
        this.version = version;
        setPath(path);
    }

    /** @return the key version the file holds */
    public int getVersion() {
        return version;
    }

    /** @param version the key version the file holds */
    public void setVersion(int version) {
        this.version = version;
    }

    /** @return the wrapped DEK file's path; empty when unset */
    public String getPath() {
        return path;
    }

    /** @param path the wrapped DEK file's path; {@code null} reads as empty */
    public void setPath(String path) {
        this.path = path == null ? "" : path;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof KeyFileOptions that && version == that.version && path.equals(that.path);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, path);
    }

    @Override
    public String toString() {
        return "KeyFileOptions[version=" + version + ", path=" + path + "]";
    }
}
