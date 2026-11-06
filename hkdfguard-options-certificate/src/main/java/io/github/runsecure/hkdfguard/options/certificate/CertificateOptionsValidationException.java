package io.github.runsecure.hkdfguard.options.certificate;

import java.io.Serial;
import java.util.List;

/**
 * {@link CertificateOptions} that break one or more rules; {@link #getFailures()} lists every one.
 * The Java counterpart of the {@code OptionsValidationException} .NET's loader throws, shaped like
 * {@code hkdfguard-options}' {@code OptionsValidationException}, with the options' name too.
 */
public final class CertificateOptionsValidationException extends IllegalArgumentException {
    @Serial
    private static final long serialVersionUID = 1L;

    /** The options' name; empty for unnamed options. */
    private final String optionsName;

    /** Every rule broken, in the order found: an array, not a List, so the exception stays serializable. */
    private final String[] failures;

    /**
     * An exception listing every failure.
     *
     * @param optionsName the options' name, for named options; {@code null} or empty for unnamed ones
     * @param failures    every rule broken, in the order found
     */
    public CertificateOptionsValidationException(String optionsName, List<String> failures) {
        super((optionsName == null || optionsName.isEmpty() ? "Certificate options are invalid: " : "Certificate options '" + optionsName + "' are invalid: ")
                + String.join(" ", failures));
        this.optionsName = optionsName == null ? "" : optionsName;
        this.failures = failures.toArray(String[]::new);
    }

    /** {@return the options' name; empty for unnamed options} */
    public String getOptionsName() {
        return optionsName;
    }

    /** {@return every rule broken, in the order found} */
    public List<String> getFailures() {
        return List.of(failures);
    }
}
