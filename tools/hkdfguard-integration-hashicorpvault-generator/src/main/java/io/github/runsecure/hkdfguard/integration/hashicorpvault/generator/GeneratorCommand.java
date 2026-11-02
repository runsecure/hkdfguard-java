package io.github.runsecure.hkdfguard.integration.hashicorpvault.generator;

import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;

/**
 * The generator's command line: [--spec &lt;openapi.json&gt;] [--settings &lt;generator.json&gt;]
 * [--output &lt;directory&gt;]. The spec and output default to the library's own, found from the
 * repository root - the directory holding hkdfguard-java's parent pom.xml, at or above the current
 * one - and the settings to generator.json beside the spec, if there is one (see
 * {@link VaultClientGenerator}). Files are only rewritten when they change, and .java files under
 * the output that the spec no longer produces are deleted. Run it from hkdfguard-java with the JDK's
 * source launcher:
 *
 * <pre>
 * java tools/hkdfguard-integration-hashicorpvault-generator/src/main/java/io/github/runsecure/hkdfguard/integration/hashicorpvault/generator/GeneratorCommand.java
 * </pre>
 */
public final class GeneratorCommand {
    /** The settings file looked for beside the spec. */
    public static final String SETTINGS_FILE_NAME = "generator.json";

    /** The library's directory under the repository root. */
    public static final String LIBRARY = "hkdfguard-integration-hashicorpvault";

    private GeneratorCommand() {
    }

    /** Runs the command; exits with its code when that isn't 0. */
    public static void main(String[] args) {
        var code = run(List.of(args), Path.of("").toAbsolutePath(), System.out, System.err);
        if (code != 0)
            System.exit(code);
    }

    /**
     * Runs the command.
     *
     * @return 0 on success, 2 for bad arguments or no repository root
     * @throws IllegalArgumentException the spec or settings are refused by the generator
     * @throws UncheckedIOException     a file can't be read or written
     */
    public static int run(List<String> args, Path currentDirectory, PrintStream output, PrintStream error) {
        Path spec = null;
        Path settings = null;
        Path outputDirectory = null;
        for (var i = 0; i < args.size(); i++) {
            var argument = args.get(i);
            var hasValue = i + 1 < args.size();
            switch (argument) {
                case "--spec" -> {
                    if (!hasValue)
                        return usage(argument, error);
                    spec = currentDirectory.resolve(args.get(++i));
                }
                case "--settings" -> {
                    if (!hasValue)
                        return usage(argument, error);
                    settings = currentDirectory.resolve(args.get(++i));
                }
                case "--output" -> {
                    if (!hasValue)
                        return usage(argument, error);
                    outputDirectory = currentDirectory.resolve(args.get(++i));
                }
                default -> {
                    return usage(argument, error);
                }
            }
        }

        if (spec == null || outputDirectory == null) {
            var root = repositoryRoot(currentDirectory);
            if (root == null) {
                error.println("Couldn't find the repository root (hkdfguard-java's parent pom.xml) at or above the current directory; "
                        + "run from inside it, or pass --spec and --output.");
                return 2;
            }

            var library = root.resolve(LIBRARY);
            if (spec == null)
                spec = library.resolve("openapi.json");
            if (outputDirectory == null)
                outputDirectory = library.resolve("src").resolve("generated").resolve("java");
        }

        spec = spec.toAbsolutePath().normalize();
        outputDirectory = outputDirectory.toAbsolutePath().normalize();
        if (settings == null)
            settings = spec.resolveSibling(SETTINGS_FILE_NAME);
        settings = settings.toAbsolutePath().normalize();

        try {
            var hasSettings = Files.isRegularFile(settings);
            var files = VaultClientGenerator.generate(Files.readString(spec, StandardCharsets.UTF_8),
                    hasSettings ? Files.readString(settings, StandardCharsets.UTF_8) : null);

            var written = 0;
            var expected = new HashSet<Path>();
            for (var file : files.entrySet()) {
                var path = outputDirectory.resolve(file.getKey()).normalize();
                expected.add(path);
                if (Files.isRegularFile(path) && Files.readString(path, StandardCharsets.UTF_8).replace("\r\n", "\n").equals(file.getValue()))
                    continue;

                Files.createDirectories(path.getParent());
                Files.writeString(path, file.getValue(), StandardCharsets.UTF_8);
                written++;
            }

            var deleted = 0;
            if (Files.isDirectory(outputDirectory)) {
                List<Path> stale;
                try (var walk = Files.walk(outputDirectory)) {
                    stale = walk.filter(p -> p.getFileName().toString().endsWith(".java") && Files.isRegularFile(p))
                            .map(Path::normalize)
                            .filter(p -> !expected.contains(p))
                            .toList();
                }
                for (var path : stale) {
                    Files.delete(path);
                    deleted++;
                }
            }

            output.println(files.size() + " files from " + spec + (hasSettings ? " with " + settings : "") + ": " + written + " written, "
                    + (files.size() - written) + " unchanged, " + deleted + " stale deleted, in " + outputDirectory + ".");
            return 0;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static int usage(String argument, PrintStream error) {
        error.println("Unknown argument '" + argument + "'. Usage: [--spec <openapi.json>] [--settings <generator.json>] [--output <directory>]");
        return 2;
    }

    // The directory at or above start holding the parent POM: a pom.xml whose artifactId is hkdfguard-parent.
    static Path repositoryRoot(Path start) {
        for (var directory = start.toAbsolutePath(); directory != null; directory = directory.getParent()) {
            var pom = directory.resolve("pom.xml");
            try {
                if (Files.isRegularFile(pom) && Files.readString(pom, StandardCharsets.UTF_8).contains("<artifactId>hkdfguard-parent</artifactId>")
                        && !Files.readString(pom, StandardCharsets.UTF_8).contains("<parent>"))
                    return directory;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return null;
    }
}
