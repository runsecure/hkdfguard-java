package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import com.azure.core.exception.HttpResponseException;
import java.util.Map;

/** Reads Key Vault's error code - "Forbidden", "KeyNotFound", ... - from a refusal. */
final class KeyVaultErrors {
    private KeyVaultErrors() {
    }

    /** The {@code error.code} of the response body, or "error" if there is none. */
    static String code(HttpResponseException e) {
        if (e.getValue() instanceof Map<?, ?> body && body.get("error") instanceof Map<?, ?> error
                && error.get("code") instanceof String code && !code.isEmpty())
            return code;
        return "error";
    }
}
