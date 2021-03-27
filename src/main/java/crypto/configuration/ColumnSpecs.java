package crypto.configuration;

import java.util.Map;

public class ColumnSpecs {
    private String column;
    private String algorithm;

    private Map<String, String> params;

    public ColumnSpecs(String column, String algorithm, Map<String, String> params) {
        this.column = column;
        this.algorithm = algorithm;
        this.params = params;
    }

    public String getColumn() {
        return column;
    }

    public void setColumn(String column) {
        this.column = column;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }
}
