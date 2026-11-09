package io.github.runsecure.hkdfguard.systemdcredentials;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A stand-in for systemd-creds that ProcessSystemdCredsRunnerTest starts as a real child process,
 * on any OS: "echo EXIT" copies stdin to stdout, writes a note to stderr and exits with EXIT;
 * "flood COUNT" writes COUNT bytes to stdout without reading stdin; "hang PIDFILE JAVA CLASSPATH"
 * starts a grandchild that hangs too, writes both process ids to PIDFILE, and hangs.
 */
public final class TestProcess {
    private TestProcess() {
    }

    public static void main(String[] args) throws Exception {
        switch (args[0]) {
            case "echo" -> {
                var input = System.in.readAllBytes();
                System.out.write(input);
                System.out.flush();
                System.err.print("echoed " + input.length + " bytes\n");
                System.err.flush();
                System.exit(Integer.parseInt(args[1]));
            }
            case "flood" -> {
                var count = Integer.parseInt(args[1]);
                var block = new byte[64 * 1024];
                for (var i = 0; i < block.length; i++)
                    block[i] = (byte) i;
                for (var written = 0; written < count; written += block.length)
                    System.out.write(block, 0, Math.min(block.length, count - written));
                System.out.flush();
            }
            case "hang" -> {
                var pidFile = Path.of(args[1]);
                if (args.length > 2) {
                    var child = new ProcessBuilder(args[2], "-cp", args[3], TestProcess.class.getName(), "hang", args[1] + ".child")
                            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                            .redirectError(ProcessBuilder.Redirect.DISCARD)
                            .start();
                    Files.writeString(pidFile, ProcessHandle.current().pid() + " " + child.pid(), StandardCharsets.US_ASCII);
                } else {
                    Files.writeString(pidFile, Long.toString(ProcessHandle.current().pid()), StandardCharsets.US_ASCII);
                }
                Thread.sleep(120_000);
            }
            default -> throw new IOException("Unknown mode " + args[0]);
        }
    }
}
