package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.time.Duration;
import java.util.Locale;

/** Go's duration syntax - "1h30m", "300ms", "2.5s" - which Vault and its environment variables use. */
final class GoDuration {
    private static final BigInteger MAX_NANOS = BigInteger.valueOf(Long.MAX_VALUE).multiply(BigInteger.valueOf(1_000_000_000L))
            .add(BigInteger.valueOf(999_999_999L));

    private GoDuration() {
    }

    /**
     * time.ParseDuration: an optional sign, then one or more decimal numbers each with a unit (ns,
     * us, µs, ms, s, m, h); "0" alone needs none.
     *
     * @throws IllegalArgumentException value isn't a duration, or is longer than a Duration holds
     */
    static Duration parse(String value) {
        var s = value;
        var negative = false;
        if (!s.isEmpty() && (s.charAt(0) == '-' || s.charAt(0) == '+')) {
            negative = s.charAt(0) == '-';
            s = s.substring(1);
        }

        if (s.equals("0"))
            return Duration.ZERO;
        if (s.isEmpty())
            throw new IllegalArgumentException("Invalid duration '" + value + "'.");

        var nanoseconds = BigDecimal.ZERO;
        var i = 0;
        while (i < s.length()) {
            var start = i;
            while (i < s.length() && (isDigit(s.charAt(i)) || s.charAt(i) == '.'))
                i++;
            var number = s.substring(start, i);
            if (number.isEmpty() || number.equals(".") || number.indexOf('.') != number.lastIndexOf('.'))
                throw new IllegalArgumentException("Invalid duration '" + value + "'.");

            var unitStart = i;
            while (i < s.length() && !isDigit(s.charAt(i)) && s.charAt(i) != '.')
                i++;
            var unit = s.substring(unitStart, i);
            long perUnit = switch (unit) {
                case "ns" -> 1;
                case "us", "µs", "μs" -> 1_000;
                case "ms" -> 1_000_000;
                case "s" -> 1_000_000_000;
                case "m" -> 60_000_000_000L;
                case "h" -> 3_600_000_000_000L;
                case "" -> throw new IllegalArgumentException("Missing unit in duration '" + value + "'.");
                default -> throw new IllegalArgumentException("Unknown unit '" + unit + "' in duration '" + value + "'.");
            };

            nanoseconds = nanoseconds.add(new BigDecimal(number.startsWith(".") ? "0" + number : number).multiply(BigDecimal.valueOf(perUnit)));
        }

        var nanos = nanoseconds.setScale(0, RoundingMode.DOWN).toBigIntegerExact();
        if (nanos.compareTo(MAX_NANOS) > 0)
            throw new IllegalArgumentException("The duration '" + value + "' is too long.");

        var seconds = nanos.divideAndRemainder(BigInteger.valueOf(1_000_000_000L));
        var duration = Duration.ofSeconds(seconds[0].longValueExact(), seconds[1].longValueExact());
        return negative ? duration.negated() : duration;
    }

    /** Duration.String: "1h2m3.5s", "5m0s", "1.5ms", "0s". */
    static String format(Duration duration) {
        if (duration.isZero())
            return "0s";

        var result = new StringBuilder();
        if (duration.isNegative())
            result.append('-');
        var nanoseconds = BigInteger.valueOf(duration.getSeconds()).multiply(BigInteger.valueOf(1_000_000_000L))
                .add(BigInteger.valueOf(duration.getNano())).abs();

        if (nanoseconds.compareTo(BigInteger.valueOf(1_000_000_000L)) < 0) {
            var n = nanoseconds.longValueExact();
            if (n < 1_000)
                return result.append(n).append("ns").toString();
            if (n < 1_000_000)
                return result.append(fraction(BigInteger.valueOf(n), 1_000)).append("µs").toString();
            return result.append(fraction(BigInteger.valueOf(n), 1_000_000)).append("ms").toString();
        }

        var minuteNanos = BigInteger.valueOf(60_000_000_000L);
        var minutes = nanoseconds.divide(minuteNanos);
        var hours = minutes.divide(BigInteger.valueOf(60));
        if (hours.signum() > 0)
            result.append(hours).append('h');
        if (minutes.signum() > 0)
            result.append(minutes.mod(BigInteger.valueOf(60))).append('m');
        return result.append(fraction(nanoseconds.mod(minuteNanos), 1_000_000_000L)).append('s').toString();
    }

    // value / unit, with as many fractional digits as it needs.
    private static String fraction(BigInteger value, long unit) {
        var divided = value.divideAndRemainder(BigInteger.valueOf(unit));
        var whole = divided[0].toString();
        var fraction = divided[1].longValueExact();
        if (fraction == 0)
            return whole;

        var width = Long.toString(unit).length() - 1;
        var digits = String.format(Locale.ROOT, "%0" + width + "d", fraction);
        var end = digits.length();
        while (digits.charAt(end - 1) == '0')
            end--;
        return whole + "." + digits.substring(0, end);
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }
}
