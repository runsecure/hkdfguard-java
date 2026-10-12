package io.github.runsecure.hkdfguard.options;

import java.io.Serial;
import java.util.List;

/** {@link HkdfGuardOptions} that break one or more rules; {@link #getFailures()} lists every one. */
public final class OptionsValidationException extends IllegalArgumentException {
    @Serial
    private static final long serialVersionUID = 1L;

    // An array, not a List, so the exception stays serializable.
    private final String[] failures;

    /** @param failures every rule broken, in the order found */
    public OptionsValidationException(List<String> failures) {
        super("HkdfGuard options are invalid: " + String.join(" ", failures));
        this.failures = failures.toArray(String[]::new);
    }

    /** @return every rule broken, in the order found */
    public List<String> getFailures() {
        return List.of(failures);
    }
}
