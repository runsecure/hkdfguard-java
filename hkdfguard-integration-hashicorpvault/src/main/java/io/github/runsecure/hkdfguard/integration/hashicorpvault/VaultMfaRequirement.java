package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.util.List;
import java.util.Map;

/**
 * The multi-factor validation a login needs.
 *
 * @param mfaRequestId   the id to validate against (sys/mfa/validate)
 * @param mfaConstraints the constraints, by name: each satisfied by any one of its methods
 */
public record VaultMfaRequirement(String mfaRequestId, Map<String, ConstraintAny> mfaConstraints) {
    /**
     * A constraint any one of whose methods satisfies it.
     *
     * @param any the methods that satisfy it
     */
    public record ConstraintAny(List<MethodId> any) {
    }

    /**
     * An MFA method.
     *
     * @param type          the method's type: totp, duo, okta or pingid
     * @param id            the method's id
     * @param usesPasscode  whether it takes a passcode
     */
    public record MethodId(String type, String id, boolean usesPasscode) {
    }

    static VaultMfaRequirement fromJson(JsonValue json) {
        json.requireObject("mfa_requirement");
        return new VaultMfaRequirement(json.member("mfa_request_id").readString(),
                json.member("mfa_constraints").readMap(constraint -> constraint.readModel(c -> new ConstraintAny(
                        c.requireObject("mfa_constraints").member("any").readList(method -> method.readModel(m -> new MethodId(
                                m.requireObject("any").member("type").readString(),
                                m.member("id").readString(),
                                Boolean.TRUE.equals(m.member("uses_passcode").readBoolean()))))))));
    }
}
