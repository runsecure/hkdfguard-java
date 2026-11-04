package io.github.runsecure.hkdfguard.systemdcredentials;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The real runner, against real child processes - a JVM running TestProcess in systemd-creds'
 * place - so its argument list, pipes, exit codes, timeout and process-tree kill are tested on any
 * OS, Windows included.
 */
class ProcessSystemdCredsRunnerTest {
    private static final String JAVA = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    private static final String CLASSPATH = Path.of("target", "test-classes").toAbsolutePath().toString();

    @TempDir
    Path folder;

    private static List<String> arguments(String... mode) {
        var arguments = new ArrayList<>(List.of("-cp", CLASSPATH, TestProcess.class.getName()));
        arguments.addAll(List.of(mode));
        return arguments;
    }

    private static boolean dies(long pid) throws InterruptedException {
        for (var i = 0; i < 100; i++) {
            if (ProcessHandle.of(pid).map(h -> !h.isAlive()).orElse(true))
                return true;
            Thread.sleep(100);
        }
        return false;
    }

    private long[] pids(Path pidFile, int count) throws Exception {
        for (var i = 0; i < 300; i++) {
            if (Files.exists(pidFile)) {
                var parts = Files.readString(pidFile, StandardCharsets.US_ASCII).trim().split(" ");
                if (parts.length == count) {
                    var pids = new long[count];
                    for (var j = 0; j < count; j++)
                        pids[j] = Long.parseLong(parts[j]);
                    return pids;
                }
            }
            Thread.sleep(50);
        }
        throw new AssertionError("The test process never wrote its process ids.");
    }

    @Test
    void stdin_GoesToTheProcess_StdoutAndStderrComeBack_WithItsExitCode() throws Exception {
        var input = "pässwörd".getBytes(StandardCharsets.UTF_8);

        var result = ProcessSystemdCredsRunner.INSTANCE.run(JAVA, arguments("echo", "3"), input, Duration.ofSeconds(60));

        try (var output = result.output()) {
            assertEquals(3, result.exitCode());
            var value = new byte[output.getLength()];
            output.copyTo(value);
            assertArrayEquals(input, value);
            assertEquals("echoed " + input.length + " bytes\n", result.error());
        }
    }

    @Test
    void aLargeStdin_AndNone_BothReachTheProcess() throws Exception {
        var large = new byte[300 * 1024];
        for (var i = 0; i < large.length; i++)
            large[i] = (byte) (i * 31);

        var result = ProcessSystemdCredsRunner.INSTANCE.run(JAVA, arguments("echo", "0"), large, Duration.ofSeconds(60));
        try (var output = result.output()) {
            var value = new byte[output.getLength()];
            output.copyTo(value);
            assertArrayEquals(large, value);
        }

        var empty = ProcessSystemdCredsRunner.INSTANCE.run(JAVA, arguments("echo", "0"), new byte[0], Duration.ofSeconds(60));
        try (var output = empty.output()) {
            assertEquals(0, output.getLength());
        }
    }

    @Test
    void stdoutOverSystemdsLimit_FailsTheRun() {
        assertThrows(io.github.runsecure.hkdfguard.cache.InvalidSecretDataException.class,
                () -> ProcessSystemdCredsRunner.INSTANCE.run(JAVA, arguments("flood", Integer.toString(SystemdCredential.MAX_LENGTH + 1)), new byte[0],
                        Duration.ofSeconds(60)));
    }

    @Test
    void aRunThatOutlastsTheTimeout_IsKilled_WithEverythingItStarted() throws Exception {
        var pidFile = folder.resolve("pids");

        var ex = assertThrows(TimeoutException.class,
                () -> ProcessSystemdCredsRunner.INSTANCE.run(JAVA, arguments("hang", pidFile.toString(), JAVA, CLASSPATH), new byte[0], Duration.ofSeconds(8)));

        assertEquals("systemd-creds didn't finish within PT8S.", ex.getMessage());
        var pids = pids(pidFile, 2);
        assertTrue(dies(pids[0]), "the process outlived its timeout");
        assertTrue(dies(pids[1]), "the process it started outlived its timeout");
    }

    @Test
    void anInterruptedRun_IsKilled_WithEverythingItStarted() throws Exception {
        var pidFile = folder.resolve("pids");
        var thread = new Thread[1];
        var running = new CompletableFuture<Throwable>();
        thread[0] = Thread.ofVirtual().start(() -> {
            try {
                ProcessSystemdCredsRunner.INSTANCE.run(JAVA, arguments("hang", pidFile.toString(), JAVA, CLASSPATH), new byte[0], Duration.ofSeconds(120));
                running.complete(null);
            } catch (Throwable t) {
                running.complete(t);
            }
        });

        var pids = pids(pidFile, 2);
        thread[0].interrupt();

        assertTrue(running.get(30, TimeUnit.SECONDS) instanceof InterruptedException);
        assertTrue(dies(pids[0]), "the process outlived the interrupt");
        assertTrue(dies(pids[1]), "the process it started outlived the interrupt");
    }

    @Test
    void anExecutableThatDoesntExist_DoesntStart() {
        var missing = folder.resolve("no-such-systemd-creds").toString();

        var ex = assertThrows(UncheckedIOException.class, () -> ProcessSystemdCredsRunner.INSTANCE.run(missing, List.of(), new byte[0], Duration.ofSeconds(5)));

        assertTrue(ex.getMessage().startsWith(missing + " didn't start"), ex.getMessage());
        assertFalse(Files.exists(Path.of(missing)));
    }
}
