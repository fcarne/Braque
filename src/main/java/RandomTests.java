import org.apache.commons.math3.distribution.HypergeometricDistribution;
import org.renjin.script.RenjinScriptEngineFactory;
import org.renjin.sexp.DoubleArrayVector;

import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.util.ArrayList;

public class RandomTests {
    public static void main(String[] args) {

        RenjinScriptEngineFactory factory = new RenjinScriptEngineFactory();
        ScriptEngine engine = factory.getScriptEngine();

        ArrayList<Integer> list = new ArrayList<>();
        long start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            engine.put("s", "1234");
            engine.put("m", 1000);
            engine.put("n", 2500);
            engine.put("k", 500);
            try {
                list.add(((DoubleArrayVector) engine.eval("rhyper(1, m, n, k) ")).asInt());
            } catch (ScriptException e) {
                e.printStackTrace();
            }
        }
        list.stream().mapToDouble(a -> a).average().ifPresent(System.out::println);
        System.out.println("TIME R: " + (System.currentTimeMillis() - start));

        list.clear();
        start = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            list.add(new HypergeometricDistribution(3500, 1000, 500).sample());
        }
        list.stream().mapToDouble(a -> a).average().ifPresent(System.out::println);
        System.out.println("TIME Apache: " + (System.currentTimeMillis() - start));

    }
}
