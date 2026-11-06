package io.github.runsecure.hkdfguard.systemdcredentials;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeoutException;

/** Runs systemd-creds with arguments, writing stdin to it; the tests run a fake. */
interface SystemdCredsRunner {
    /** What one systemd-creds run gave back: its exit code, stdout - the caller closes it - and stderr. */
    record Result(int exitCode, SystemdCredential output, String error) {
    }

    /**
     * Runs executablePath with arguments, blocking until it exits.
     *
     * @throws TimeoutException     it didn't finish within timeout, and was killed with everything it started
     * @throws InterruptedException the calling thread was interrupted - the run cancelled - and it was killed likewise
     */
    Result run(String executablePath, List<String> arguments, byte[] stdin, Duration timeout) throws TimeoutException, InterruptedException;
}
