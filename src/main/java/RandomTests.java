import org.apache.commons.math3.distribution.HypergeometricDistribution;
import org.renjin.script.RenjinScriptEngineFactory;
import org.renjin.sexp.DoubleArrayVector;

import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;

public class RandomTests {

    public static void main(String[] args) {
        //providerAlgorithms();
        renjinEngineSetupTime(1000);
        renjinVSCommons(1000000, 2500000, 650000, 20);
    }

    public static void providerAlgorithms() {
        for (Provider provider : Security.getProviders()) {
            System.out.println("Provider: " + provider.getName());
            for (Provider.Service service : provider.getServices()) {
                System.out.println("  Algorithm: " + service.getAlgorithm());
            }
        }
    }

    public static void renjinEngineSetupTime(int reps) {
        long start = System.currentTimeMillis();
        for (int i = 0; i < reps; i++) {
            RenjinScriptEngineFactory factory = new RenjinScriptEngineFactory();
            factory.getScriptEngine();
        }
        long stop = System.currentTimeMillis();
        System.out.println("Engine setup (x" + reps + "): " + (stop - start) + "ms");
        System.out.println("Engine setup: " + (stop - start) / (double) reps + "ms");
    }

    public static void renjinVSCommons(int w, int b, int d, int reps) {
        RenjinScriptEngineFactory factory = new RenjinScriptEngineFactory();
        ScriptEngine engine = factory.getScriptEngine();

        ArrayList<Integer> list = new ArrayList<>();

        long start = System.currentTimeMillis();
        engine.put("w", w);
        engine.put("b", b);
        engine.put("d", d);
        for (int i = 0; i < reps; i++) {
            try {
                list.add(((DoubleArrayVector) engine.eval("rhyper(1, w, b, d) ")).asInt());
            } catch (ScriptException e) {
                e.printStackTrace();
            }
        }
        list.stream().mapToDouble(a -> a).average().ifPresent(System.out::println);
        System.out.println("TIME R: " + (System.currentTimeMillis() - start) + "ms");

        list.clear();

        start = System.currentTimeMillis();
        HypergeometricDistribution hg = new HypergeometricDistribution(w + b, w, d);
        for (int i = 0; i < reps; i++) {
            list.add(hg.sample());
        }
        list.stream().mapToDouble(a -> a).average().ifPresent(System.out::println);
        System.out.println("TIME Apache: " + (System.currentTimeMillis() - start) + "ms");
    }
}

