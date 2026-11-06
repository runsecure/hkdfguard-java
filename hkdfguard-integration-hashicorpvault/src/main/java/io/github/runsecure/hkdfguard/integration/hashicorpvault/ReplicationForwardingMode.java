package io.github.runsecure.hkdfguard.integration.hashicorpvault;

/** Whether a performance standby forwards requests to the active node (Vault Enterprise). */
public enum ReplicationForwardingMode {
    /** No forwarding header. */
    NONE,

    /**
     * X-Vault-Forward: a performance standby forwards every request to the active node; see
     * https://developer.hashicorp.com/vault/docs/enterprise/consistency#unconditional-forwarding-performance-standbys-only.
     */
    ALWAYS,

    /**
     * X-Vault-Inconsistent: a performance standby forwards a request to the active node only when it
     * hasn't caught up with the replication state it requires - see
     * {@link VaultReplication#requireReplicationStates} and
     * https://developer.hashicorp.com/vault/docs/enterprise/consistency#conditional-forwarding-performance-standbys-only.
     */
    INCONSISTENT,
}
