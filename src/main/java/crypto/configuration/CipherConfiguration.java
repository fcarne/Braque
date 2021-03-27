package crypto.configuration;

import java.io.File;
import java.util.HashMap;

public class CipherConfiguration {

    private File input;
    private File output;
    private HashMap<String, ColumnSpecs> specs;

    public CipherConfiguration(File input, File output, HashMap<String, ColumnSpecs> specs) {
        this.input = input;
        this.output = output;
        this.specs = specs;
    }

    public File getInput() {
        return input;
    }

    public void setInput(File input) {
        this.input = input;
    }

    public File getOutput() {
        return output;
    }

    public void setOutput(File output) {
        this.output = output;
    }

    public HashMap<String, ColumnSpecs> getSpecs() {
        return specs;
    }

    public void setSpecs(HashMap<String, ColumnSpecs> specs) {
        this.specs = specs;
    }
}
