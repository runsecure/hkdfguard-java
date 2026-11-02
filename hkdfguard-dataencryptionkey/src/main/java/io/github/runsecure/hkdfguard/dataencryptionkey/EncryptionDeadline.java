package io.github.runsecure.hkdfguard.dataencryptionkey;

import java.time.Instant;
import java.util.Objects;

/**
 * A wall-clock point after which a key stops encrypting, and an earlier one from which that is
 * announced. Decryption is never limited. {@link KeyRingBuilder} gives every key-file key one, from
 * the file's age, so a key file that is never rotated stops encrypting rather than encrypting
 * without bound: the per-process encryption budget can't see earlier runs of the process.
 *
 * @param warnAt     from when {@code onWarning} is called, once
 * @param refuseAt   from when encrypt throws {@link io.github.runsecure.hkdfguard.abstractions.EncryptionLimitReachedException}
 * @param reason     that exception's message
 * @param onWarning  called once, the first time the deadline is checked at or after warnAt but
 *                   before refuseAt; may be null
 * @param onExpired  called once, the first time the deadline is checked at or after refuseAt; may
 *                   be null
 */
public record EncryptionDeadline(Instant warnAt, Instant refuseAt, String reason, Runnable onWarning, Runnable onExpired) {
    /** @throws NullPointerException warnAt, refuseAt or reason is null */
    public EncryptionDeadline {
        Objects.requireNonNull(warnAt, "warnAt");
        Objects.requireNonNull(refuseAt, "refuseAt");
        Objects.requireNonNull(reason, "reason");
    }
}
