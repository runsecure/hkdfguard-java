package io.github.runsecure.hkdfguard.systemdcredentials;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;

/**
 * Encrypts and decrypts Linux credentials with systemd-creds, which binds each to this machine's
 * host key, its TPM, or both ({@link SystemdCredentialsOptions#getKey()}), and to its name: a
 * credential renamed fails to decrypt. The plaintext never touches a file or a command line:
 * encrypting writes it to systemd-creds' stdin, and decrypting reads it from systemd-creds' stdout
 * into a {@link SystemdCredential}.
 *
 * <pre>{@code
 * // At deploy, on the machine itself (as root, for system credentials):
 * credentials.encryptAsync("tls-password", password, "/etc/credstore.encrypted/tls-password.cred").join();
 *
 * // In the service: LoadCredentialEncrypted=tls-password:/etc/credstore.encrypted/tls-password.cred
 * // in its unit has systemd decrypt it into memory under /run, which readLoadedCredential reads -
 * // or, with the privilege to, decrypt it directly:
 * try (var value = credentials.decryptAsync("tls-password", "/etc/credstore.encrypted/tls-password.cred").join()) {
 *     ...
 * }
 * }</pre>
 *
 * <p>Decrypting a system credential directly needs what encrypting it used: root, for the host key,
 * and access to the TPM (the tss group, say) for a TPM-bound one. An unprivileged service reads it
 * through LoadCredentialEncrypted= instead, which systemd decrypts for it into the service's own
 * unswappable in-memory credentials directory ({@link #readLoadedCredential(String)}), or uses
 * {@link SystemdCredentialsOptions#isUserScope() user-scope} credentials.
 *
 * <p>Each run of systemd-creds is on a virtual thread of its own. Argument errors throw from the
 * call itself; a failed run completes the future exceptionally - {@link IllegalStateException} for a
 * non-zero exit, {@link TimeoutException} when it outlasted the timeout and was killed. Cancelling
 * the future kills the run, and everything it started.
 */
public final class SystemdCredentials {
    /** The environment variable systemd names a service's credentials directory in. */
    public static final String CREDENTIALS_DIRECTORY_VARIABLE = "CREDENTIALS_DIRECTORY";

    /** The longest credential name. */
    public static final int MAX_NAME_LENGTH = 255;

    private final String executablePath;
    private final SystemdCredentialKey key;
    private final boolean userScope;
    private final Duration timeout;
    private final SystemdCredsRunner runner;

    /**
     * Credentials with the default options: /usr/bin/systemd-creds, {@link SystemdCredentialKey#AUTO}.
     *
     * @throws UnsupportedOperationException not Linux
     */
    public SystemdCredentials() {
        this(null);
    }

    /**
     * Credentials run as options say.
     *
     * @param options where systemd-creds is and how to run it; {@code null} for the defaults
     * @throws UnsupportedOperationException not Linux
     * @throws IllegalArgumentException      the executable path isn't absolute, the key is null, or the
     *                                       timeout isn't positive
     */
    public SystemdCredentials(SystemdCredentialsOptions options) {
        this(options, ProcessSystemdCredsRunner.INSTANCE);
        requireLinux(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("linux"));
    }

    /** Runs systemd-creds through runner, on any OS, for tests. */
    SystemdCredentials(SystemdCredentialsOptions options, SystemdCredsRunner runner) {
        options = options == null ? new SystemdCredentialsOptions() : options;
        var path = options.getExecutablePath();
        if (path == null || path.isEmpty() || path.charAt(0) != '/')
            throw new IllegalArgumentException("The systemd-creds path must be absolute, not '" + path + "'.");
        if (options.getKey() == null)
            throw new IllegalArgumentException("The key must be AUTO, HOST, TPM2 or HOST_AND_TPM2, not null.");
        if (options.getTimeout() == null || options.getTimeout().isNegative() || options.getTimeout().isZero())
            throw new IllegalArgumentException("The timeout must be positive, not " + options.getTimeout() + ".");

        this.executablePath = path;
        this.key = options.getKey();
        this.userScope = options.isUserScope();
        this.timeout = options.getTimeout();
        this.runner = runner;
    }

    /** @throws UnsupportedOperationException isLinux is false */
    static void requireLinux(boolean isLinux) {
        if (!isLinux)
            throw new UnsupportedOperationException("systemd-creds runs only on Linux.");
    }

    /**
     * Whether name can be a credential's name: 1-{@link #MAX_NAME_LENGTH} ASCII letters, digits,
     * '.', '_' and '-', not "." or "..", and not starting with '-', so it is always a file name and
     * never an option.
     *
     * @param name the name to check; {@code null} is not one
     * @return whether it is a credential name
     */
    public static boolean isValidName(String name) {
        if (name == null || name.isEmpty() || name.length() > MAX_NAME_LENGTH || name.equals(".") || name.equals("..") || name.charAt(0) == '-')
            return false;
        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
                return false;
        }
        return true;
    }

    /**
     * Encrypts plaintext as the credential name, written to outputPath - {@code systemd-creds encrypt
     * --name=name} - with the plaintext on its stdin. plaintext is the caller's, and isn't zeroed;
     * don't change it until the future completes.
     *
     * @param name       the credential's name, which it is bound to
     * @param plaintext  the value to encrypt
     * @param outputPath where the encrypted credential is written, an absolute path
     * @return completes once the credential file is written
     * @throws IllegalArgumentException name isn't one (see {@link #isValidName}), or outputPath isn't absolute
     * @throws NullPointerException     plaintext is null
     */
    public CompletableFuture<Void> encryptAsync(String name, byte[] plaintext, String outputPath) {
        Objects.requireNonNull(plaintext, "plaintext");
        return encrypt(name, plaintext, outputPath, null);
    }

    /**
     * As {@link #encryptAsync(String, byte[], String)} for text, encoded as UTF-8 into an array
     * zeroed once systemd-creds has run. plaintext is the caller's, and isn't zeroed.
     *
     * @param name       the credential's name, which it is bound to
     * @param plaintext  the text to encrypt
     * @param outputPath where the encrypted credential is written, an absolute path
     * @return completes once the credential file is written
     * @throws IllegalArgumentException name isn't one, or outputPath isn't absolute
     * @throws NullPointerException     plaintext is null
     */
    public CompletableFuture<Void> encryptAsync(String name, CharSequence plaintext, String outputPath) {
        Objects.requireNonNull(plaintext, "plaintext");
        checkName(name);
        checkPath(outputPath);
        var bytes = Utf8Utility.encode(plaintext);
        return encrypt(name, bytes, outputPath, () -> ArrayUtility.zeroMemory(bytes));
    }

    private CompletableFuture<Void> encrypt(String name, byte[] plaintext, String outputPath, Runnable afterRun) {
        try {
            checkName(name);
            checkPath(outputPath);
        } catch (RuntimeException e) {
            if (afterRun != null)
                afterRun.run();
            throw e;
        }

        var arguments = new ArrayList<String>(List.of("--name=" + name, "--with-key=" + keyArgument(key)));
        if (userScope)
            arguments.add("--user");
        arguments.addAll(List.of("encrypt", "-", outputPath));

        // Encrypting writes to outputPath, not stdout: there is nothing to keep.
        var running = run("encrypt", arguments, plaintext, afterRun, false);
        CompletableFuture<Void> done = running.thenApply(ignored -> null);
        done.whenComplete((ignored, failure) -> {
            if (done.isCancelled())
                running.cancel(true);
        });
        return done;
    }

    /**
     * Decrypts the credential name from inputPath - {@code systemd-creds decrypt --name=name} -
     * reading the value straight from its stdout. A credential encrypted under another name fails, as
     * does one encrypted on another machine.
     *
     * @param name      the name the credential was encrypted under
     * @param inputPath the encrypted credential file, an absolute path
     * @return completes with the value; close it once used, which zeroes it
     * @throws IllegalArgumentException name isn't one, or inputPath isn't absolute
     */
    public CompletableFuture<SystemdCredential> decryptAsync(String name, String inputPath) {
        checkName(name);
        checkPath(inputPath);

        var arguments = new ArrayList<String>(List.of("--name=" + name, "--newline=no"));
        if (userScope)
            arguments.add("--user");
        arguments.addAll(List.of("decrypt", inputPath, "-"));

        return run("decrypt", arguments, new byte[0], null, true);
    }

    /**
     * The credential name that systemd decrypted for this service - LoadCredentialEncrypted= or
     * SetCredentialEncrypted= in its unit - from its in-memory credentials directory
     * ({@value #CREDENTIALS_DIRECTORY_VARIABLE}) under /run, which only the service can read.
     *
     * @param name the credential's name, as the unit names it
     * @return the value, or {@code null} if it has no such credential, or isn't running with any;
     *         close it once used, which zeroes it
     * @throws IllegalArgumentException   name isn't one
     * @throws InvalidSecretDataException the credential is longer than {@link SystemdCredential#MAX_LENGTH}
     * @throws UncheckedIOException       it couldn't be read
     */
    public static SystemdCredential readLoadedCredential(String name) {
        return readLoadedCredential(name, null);
    }

    /**
     * As {@link #readLoadedCredential(String)}, from the directory given.
     *
     * @param name                 the credential's name, as the unit names it
     * @param credentialsDirectory the directory to look in; {@code null} for {@value #CREDENTIALS_DIRECTORY_VARIABLE}'s
     * @return the value, or {@code null} if there is no such credential; close it once used
     * @throws IllegalArgumentException   name isn't one
     * @throws InvalidSecretDataException the credential is longer than {@link SystemdCredential#MAX_LENGTH}
     * @throws UncheckedIOException       it couldn't be read
     */
    public static SystemdCredential readLoadedCredential(String name, String credentialsDirectory) {
        var path = loadedCredentialPath(name, credentialsDirectory);
        return path != null && Files.isRegularFile(path) ? SystemdCredential.readFile(path) : null;
    }

    /** Where the loaded credential name would be; null when there is no credentials directory. */
    static Path loadedCredentialPath(String name, String credentialsDirectory) {
        checkName(name);
        var directory = credentialsDirectory != null ? credentialsDirectory : System.getenv(CREDENTIALS_DIRECTORY_VARIABLE);
        return directory == null || directory.isEmpty() ? null : Path.of(directory, name);
    }

    // Runs systemd-creds on a virtual thread, completing the future with its stdout - or, when
    // keepOutput is false, null, its stdout zeroed. A non-zero exit fails it with stderr's message.
    // Cancelling the future interrupts the thread, which kills the run; a value it gives after
    // all is zeroed. afterRun runs once systemd-creds has, however it ends.
    private CompletableFuture<SystemdCredential> run(String verb, List<String> arguments, byte[] stdin, Runnable afterRun, boolean keepOutput) {
        var future = new CompletableFuture<SystemdCredential>();
        var thread = Thread.ofVirtual().name("systemd-creds " + verb).unstarted(() -> {
            SystemdCredential value = null;
            Throwable failure = null;
            try {
                var result = runner.run(executablePath, List.copyOf(arguments), stdin, timeout);
                if (result.exitCode() != 0) {
                    result.output().close();
                    var detail = result.error() == null || result.error().isBlank() ? "" : ": " + result.error().strip();
                    failure = new IllegalStateException("systemd-creds " + verb + " failed with exit code " + result.exitCode() + detail);
                } else if (keepOutput) {
                    value = result.output();
                } else {
                    result.output().close();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                failure = new CancellationException("systemd-creds " + verb + " was cancelled, and killed.");
            } catch (Throwable t) {
                failure = t;
            } finally {
                // Before the future completes, so a caller that sees it done never sees stdin's plaintext.
                if (afterRun != null)
                    afterRun.run();
            }
            if (failure != null)
                future.completeExceptionally(failure);
            else if (!future.complete(value) && value != null)
                value.close();
        });
        future.whenComplete((value, failure) -> {
            if (future.isCancelled())
                thread.interrupt();
        });
        thread.start();
        return future;
    }

    private static String keyArgument(SystemdCredentialKey key) {
        return switch (key) {
            case HOST -> "host";
            case TPM2 -> "tpm2";
            case HOST_AND_TPM2 -> "host+tpm2";
            case AUTO -> "auto";
        };
    }

    private static void checkName(String name) {
        if (!isValidName(name))
            throw new IllegalArgumentException("'" + name + "' isn't a credential name: 1-" + MAX_NAME_LENGTH
                    + " ASCII letters, digits, '.', '_' and '-', not starting with '-'.");
    }

    private static void checkPath(String path) {
        if (!isAbsolute(path))
            throw new IllegalArgumentException("The credential file's path must be absolute, not '" + path + "'.");
    }

    /** Whether path is fully qualified on this operating system. */
    static boolean isAbsolute(String path) {
        if (path == null || path.isEmpty())
            return false;
        try {
            return Path.of(path).isAbsolute();
        } catch (InvalidPathException e) {
            return false;
        }
    }
}
