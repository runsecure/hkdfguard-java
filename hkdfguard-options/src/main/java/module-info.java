/**
 * Key ring settings as plain data: {@link io.github.runsecure.hkdfguard.options.HkdfGuardOptions} is
 * read from configuration, validated, and applied onto a
 * {@link io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder}.
 */
module io.github.runsecure.hkdfguard.options {
    requires transitive io.github.runsecure.hkdfguard.dataencryptionkey;

    exports io.github.runsecure.hkdfguard.options;
}
