package io.github.runsecure.hkdfguard.systemdcredentials;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Runs the real systemd-creds: the executable and its arguments as an argument list, never through
 * a shell; stdin written to the process's stream in one write, then closed; stdout read off the pipe
 * into the credential's own array, in reads large enough to bypass the stream's buffer; stderr read
 * as text. Each runs on a virtual thread of its own, so a process that stops reading its stdin can't
 * block the deadline. Killed, with every process it started, if it outlasts the timeout or the
 * calling thread is interrupted.
 *
 * <p>The JDK wraps a process's stdin in a BufferedOutputStream: a write of 8 KiB or more goes
 * straight to the pipe, but a shorter one - a password - passes through that stream's buffer, which
 * Java can't reach to zero. It is flushed and closed at once, and unreachable from then on.
 *
 * <p>stdout bypasses its buffer only while the process runs. When it exits, the JDK's process reaper
 * drains what the pipe still holds into an array of its own (ProcessPipeInputStream.processExited),
 * which can't be reached to zero, and later reads come from there. systemd-creds writes the value
 * and exits at once, so the whole value may pass through that array, which lives until collected.
 */
final class ProcessSystemdCredsRunner implements SystemdCredsRunner {
    static final ProcessSystemdCredsRunner INSTANCE = new ProcessSystemdCredsRunner();

    private ProcessSystemdCredsRunner() {
    }

    @Override
    public Result run(String executablePath, List<String> arguments, byte[] stdin, Duration timeout) throws TimeoutException, InterruptedException {
        var command = new ArrayList<String>(arguments.size() + 1);
        command.add(executablePath);
        command.addAll(arguments);

        var deadline = System.nanoTime() + timeout.toNanos();
        Process process;
        try {
            process = new ProcessBuilder(command).start();
        } catch (IOException e) {
            throw new UncheckedIOException(executablePath + " didn't start: " + e.getMessage(), e);
        }

        var output = new CompletableFuture<SystemdCredential>();
        var error = new CompletableFuture<String>();
        var input = new CompletableFuture<Void>();
        Thread.ofVirtual().name("systemd-creds-stdout").start(() -> complete(output, () -> SystemdCredential.read(process.getInputStream())));
        Thread.ofVirtual().name("systemd-creds-stderr").start(() -> complete(error, () -> {
            try (var stream = process.getErrorStream()) {
                return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }));
        Thread.ofVirtual().name("systemd-creds-stdin").start(() -> complete(input, () -> {
            try (var stream = process.getOutputStream()) {
                if (stdin.length > 0)
                    stream.write(stdin);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return null;
        }));

        var succeeded = false;
        try {
            if (!process.waitFor(remaining(deadline), TimeUnit.NANOSECONDS))
                throw new TimeoutException("systemd-creds didn't finish within " + timeout + ".");
            var message = get(error, deadline, timeout);
            var value = get(output, deadline, timeout);
            try {
                // A process that exits without reading its stdin breaks the pipe; its exit code says why.
                if (process.exitValue() == 0)
                    get(input, deadline, timeout);
            } catch (RuntimeException | TimeoutException e) {
                value.close();
                throw e;
            }
            succeeded = true;
            return new Result(process.exitValue(), value, message);
        } finally {
            if (!succeeded) {
                killTree(process);
                // Whatever stdout read after all is zeroed once the reader finishes.
                output.thenAccept(SystemdCredential::close);
            }
        }
    }

    // Kills the process and every process it started: its descendants are collected first, since
    // once it has died they are no longer its descendants.
    private static void killTree(Process process) {
        var descendants = process.descendants().toList();
        process.destroyForcibly();
        descendants.forEach(ProcessHandle::destroyForcibly);
    }

    private static long remaining(long deadline) {
        return Math.max(0, deadline - System.nanoTime());
    }

    private static <T> T get(CompletableFuture<T> future, long deadline, Duration timeout) throws InterruptedException, TimeoutException {
        try {
            return future.get(remaining(deadline), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            throw new TimeoutException("systemd-creds didn't finish within " + timeout + ".");
        } catch (ExecutionException e) {
            if (e.getCause() instanceof RuntimeException runtime)
                throw runtime;
            throw new IllegalStateException(e.getCause());
        }
    }

    private interface Body<T> {
        T run();
    }

    private static <T> void complete(CompletableFuture<T> future, Body<T> body) {
        try {
            future.complete(body.run());
        } catch (Throwable t) {
            future.completeExceptionally(t);
        }
    }
}
