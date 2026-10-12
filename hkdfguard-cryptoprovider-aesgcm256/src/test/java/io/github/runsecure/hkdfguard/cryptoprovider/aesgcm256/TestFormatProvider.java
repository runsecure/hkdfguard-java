package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * The enc::v{version}::{base64} wire format, minimally - so the pipeline protector can be tested
 * without the DataEncryptionKey module, which sits above this one. The real format provider is
 * tested against this module from there.
 */
final class TestFormatProvider implements EncryptedFormatProvider {
    private static final Pattern FORMAT = Pattern.compile("enc::v(-?\\d+)::([A-Za-z0-9+/]*={0,2})");

    @Override
    public String format(KeyTrackingValue value) {
        return "enc::v" + value.keyVersion() + "::" + Base64.getEncoder().encodeToString(value.value());
    }

    @Override
    public KeyTrackingValue parse(CharSequence encrypted) {
        var match = FORMAT.matcher(encrypted);
        if (!match.matches())
            throw new EncryptedFormatException("Invalid encrypted format.");
        return new KeyTrackingValue(Integer.parseInt(match.group(1)), Base64.getDecoder().decode(match.group(2)));
    }

    @Override
    public int getMaxDecryptedLength(CharSequence encrypted) {
        return parse(encrypted).value().length;
    }
}
