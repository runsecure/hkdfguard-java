package io.github.runsecure.hkdfguard.systemdcredentials;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeoutException;

/**
 * Stands in for systemd-creds: records each run, and "encrypts" a credential into a file bound to
 * its name, which it "decrypts" only under that name - as systemd-creds refuses a renamed one.
 */
final class FakeSystemdCreds implements SystemdCredsRunner {
    record Run(String executable, List<String> arguments, byte[] stdin, byte[] stdinArray, Duration timeout) {
    }

    final List<Run> runs = new CopyOnWriteArrayList<>();
    final List<SystemdCredential> outputs = new CopyOnWriteArrayList<>();

    /** When set, every run fails with this exit code and stderr. */
    volatile Integer failExitCode;
    volatile String failError;

    /** When set, every run does this first: blocks, say, or throws. */
    volatile Interruptible before;

    interface Interruptible {
        void run() throws InterruptedException, TimeoutException;
    }

    @Override
    public Result run(String executablePath, List<String> arguments, byte[] stdin, Duration timeout) throws TimeoutException, InterruptedException {
        runs.add(new Run(executablePath, List.copyOf(arguments), stdin.clone(), stdin, timeout));
        if (before != null)
            before.run();
        if (failExitCode != null)
            return new Result(failExitCode, output(new byte[0]), failError);

        var name = arguments.stream().filter(a -> a.startsWith("--name=")).findFirst().orElseThrow().substring("--name=".length());
        try {
            if (arguments.contains("encrypt")) {
                assertEquals("-", arguments.get(arguments.size() - 2));
                Files.writeString(Path.of(arguments.get(arguments.size() - 1)), name + ":" + Base64.getEncoder().encodeToString(stdin));
                return new Result(0, output(new byte[0]), "");
            }

            assertEquals("-", arguments.get(arguments.size() - 1));
            var stored = Files.readString(Path.of(arguments.get(arguments.size() - 2)), StandardCharsets.UTF_8).split(":");
            if (!stored[0].equals(name))
                return new Result(1, output(new byte[0]), "Embedded credential name '" + stored[0] + "' does not match filename '" + name + "', refusing.\n");
            return new Result(0, output(Base64.getDecoder().decode(stored[1])), "");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private SystemdCredential output(byte[] bytes) {
        var output = SystemdCredential.read(new ByteArrayInputStream(bytes));
        outputs.add(output);
        return output;
    }
}
