package io.github.runsecure.hkdfguard.pipeline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** Reading a body into an array of the library's own. */
class ResponseBodyTest {
    @Test
    void read_ReadsTheWholeBody_GrowingAsNeeded_AndCloseZeroesIt() throws IOException {
        var body = ("{\"value\":\"" + "x".repeat(100_000) + "\"}").getBytes(StandardCharsets.UTF_8);

        var read = ResponseBody.read(new ByteArrayInputStream(body));
        assertArrayEquals(body, Arrays.copyOf(read.buffer(), read.length()));

        read.close();
        for (var b : read.buffer())
            assertEquals(0, b);
    }

    @Test
    void read_RefusesABodyOfTheMaximumOrMore() {
        assertThrows(InvalidSecretDataException.class, () -> ResponseBody.read(new ByteArrayInputStream(new byte[ResponseBody.MAX_LENGTH])));
        assertThrows(NullPointerException.class, () -> ResponseBody.read(null));
    }
}
