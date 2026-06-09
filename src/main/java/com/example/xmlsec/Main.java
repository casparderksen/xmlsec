package com.example.xmlsec;

import java.io.Console;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

@Command(
        name = "xmlsig",
        mixinStandardHelpOptions = true,
        version = "xmlsig 0.1.0",
        description = "Generate and validate detached XML Digital Signatures.",
        subcommands = { Main.Sign.class, Main.Verify.class }
)
public class Main implements Runnable {

    static final int EXIT_BAD_INPUT = 2;

    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new Main());
        cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            if (ex instanceof NoSuchFileException nsfe) {
                System.err.println("xmlsig: file not found: " + nsfe.getFile());
                return EXIT_BAD_INPUT;
            }
            if (ex instanceof FileNotFoundException) {
                System.err.println("xmlsig: file not found: " + ex.getMessage());
                return EXIT_BAD_INPUT;
            }
            throw ex;
        });
        int code = cmd.execute(args);
        System.exit(code);
    }

    @Override
    public void run() {
        CommandLine.usage(this, System.err);
    }

    @Command(
            name = "sign",
            mixinStandardHelpOptions = true,
            description = "Sign a payload XML file, writing a detached signature."
    )
    static class Sign implements Callable<Integer> {

        @Parameters(index = "0", description = "Payload XML file to sign.")
        Path payload;

        @Parameters(index = "1", description = "Output signature file.")
        Path output;

        @Parameters(index = "2", description = "PKCS12 keystore path.")
        Path keystore;

        @Override
        public Integer call() throws Exception {
            if (!checkInputFile(payload, "payload")) return EXIT_BAD_INPUT;
            if (!checkInputFile(keystore, "keystore")) return EXIT_BAD_INPUT;
            if (!checkOutputParent(output, "output")) return EXIT_BAD_INPUT;
            String password = promptPassword("Keystore password: ");
            Signer.sign(payload, output, keystore, password);
            return 0;
        }
    }

    @Command(
            name = "verify",
            mixinStandardHelpOptions = true,
            description = "Verify a detached signature."
    )
    static class Verify implements Callable<Integer> {

        @Parameters(index = "0", description = "Signature file to verify.")
        Path signature;

        @Parameters(index = "1", description = "PKCS12 keystore path (provides verification cert).")
        Path keystore;

        @Override
        public Integer call() throws Exception {
            if (!checkInputFile(signature, "signature")) return EXIT_BAD_INPUT;
            if (!checkInputFile(keystore, "keystore")) return EXIT_BAD_INPUT;
            String password = promptPassword("Keystore password: ");
            boolean ok = Verifier.verify(signature, keystore, password);
            System.out.println("Signature valid: " + ok);
            return ok ? 0 : 2;
        }
    }

    private static boolean checkInputFile(Path path, String argName) {
        if (!Files.isRegularFile(path)) {
            System.err.println("xmlsig: " + argName + ": file not found: " + path);
            return false;
        }
        if (!Files.isReadable(path)) {
            System.err.println("xmlsig: " + argName + ": file not readable: " + path);
            return false;
        }
        return true;
    }

    private static boolean checkOutputParent(Path path, String argName) {
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null && !Files.isDirectory(parent)) {
            System.err.println("xmlsig: " + argName + ": parent directory not found: " + parent);
            return false;
        }
        return true;
    }

    private static String promptPassword(String prompt) {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException(
                    "No interactive console available; password prompt requires a TTY."
            );
        }
        char[] chars = console.readPassword(prompt);
        if (chars == null || chars.length == 0) {
            throw new IllegalStateException("Empty password");
        }
        return new String(chars);
    }
}
