package terminal;

import picocli.CommandLine;

@CommandLine.Command(name = "ASCIIArt", version = "ASCIIArt 1.0", mixinStandardHelpOptions = true)
public class GaloisTerminal implements Runnable {

    @CommandLine.Parameters(paramLabel = "<word>", defaultValue = "Hello, picocli",
            description = "Words to be translated into ASCII art.")
    private final String[] words = {"Hello,", "picocli"};

    @Override
    public void run() {
        // The business logic of the command goes here...
        // In this case, code for generation of ASCII art graphics
        // (omitted for the sake of brevity).
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new GaloisTerminal()).execute(args);
        System.exit(exitCode);
    }

    public String[] getWords() {
        return words;
    }
}