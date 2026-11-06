package io.github.runsecure.hkdfguard.systemdcredentials;

/** Which key systemd-creds encrypts a credential under - its {@code --with-key}. */
public enum SystemdCredentialKey {
    /** The host key and the TPM when the machine has a TPM, the host key alone when it doesn't ("auto"). */
    AUTO,

    /** The host key, /var/lib/systemd/credential.secret, readable only by root ("host"). */
    HOST,

    /** The TPM alone, so the credential decrypts only on this machine's TPM ("tpm2"). */
    TPM2,

    /** Both: decrypting needs the host key and this machine's TPM ("host+tpm2"). */
    HOST_AND_TPM2,
}
