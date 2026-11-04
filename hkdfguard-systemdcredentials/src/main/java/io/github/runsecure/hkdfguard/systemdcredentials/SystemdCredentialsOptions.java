package io.github.runsecure.hkdfguard.systemdcredentials;

import java.time.Duration;

/**
 * How {@link SystemdCredentials} runs systemd-creds. A JavaBean, so a configuration binder can
 * populate it; {@link SystemdCredentials} checks it when constructed, and copies what it needs.
 */
public final class SystemdCredentialsOptions {
    private String executablePath = "/usr/bin/systemd-creds";
    private SystemdCredentialKey key = SystemdCredentialKey.AUTO;
    private boolean userScope;
    private Duration timeout = Duration.ofSeconds(30);

    /** The defaults: /usr/bin/systemd-creds, {@link SystemdCredentialKey#AUTO}, system credentials, 30 seconds. */
    public SystemdCredentialsOptions() {
    }

    /**
     * The systemd-creds executable, by absolute path, so no directory on PATH can stand in for it.
     *
     * @return the path; default /usr/bin/systemd-creds
     */
    public String getExecutablePath() {
        return executablePath;
    }

    /**
     * Sets the systemd-creds executable, an absolute path.
     *
     * @param executablePath the systemd-creds executable, an absolute path
     */
    public void setExecutablePath(String executablePath) {
        this.executablePath = executablePath;
    }

    /** {@return the key new credentials are encrypted under; default {@link SystemdCredentialKey#AUTO}} */
    public SystemdCredentialKey getKey() {
        return key;
    }

    /**
     * Sets the key new credentials are encrypted under.
     *
     * @param key the key new credentials are encrypted under
     */
    public void setKey(SystemdCredentialKey key) {
        this.key = key;
    }

    /**
     * Encrypts and decrypts credentials scoped to the calling user ({@code --user}; systemd 256 or
     * later), which an unprivileged account can do through systemd's credential service. Default
     * false: system credentials, which need root - or, for {@link SystemdCredentialKey#TPM2}, access
     * to the TPM - to encrypt or decrypt directly.
     *
     * @return whether credentials are the calling user's
     */
    public boolean isUserScope() {
        return userScope;
    }

    /**
     * Sets true for credentials scoped to the calling user.
     *
     * @param userScope true for credentials scoped to the calling user
     */
    public void setUserScope(boolean userScope) {
        this.userScope = userScope;
    }

    /** {@return how long one systemd-creds run may take before it is killed; default 30 seconds} */
    public Duration getTimeout() {
        return timeout;
    }

    /**
     * Sets how long one systemd-creds run may take before it is killed; positive.
     *
     * @param timeout how long one systemd-creds run may take before it is killed; positive
     */
    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

    @Override
    public String toString() {
        return "SystemdCredentialsOptions[executablePath=" + executablePath + ", key=" + key + ", userScope=" + userScope + ", timeout=" + timeout + "]";
    }
}
