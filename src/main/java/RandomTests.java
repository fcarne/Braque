import crypto.GaloisJCE;
import crypto.algorithm.util.FluentBitSet;
import org.apache.commons.math3.distribution.HypergeometricDistribution;
import org.renjin.script.RenjinScriptEngineFactory;
import org.renjin.sexp.DoubleArrayVector;

import javax.script.ScriptEngine;
import javax.script.ScriptException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

public class RandomTests {

    public static void main(String[] args) {
        FluentBitSet fluentBitSet = new FluentBitSet().set(127, 128);
        System.out.println(fluentBitSet);
        System.out.println(fluentBitSet.shiftRight(64));
        System.out.println(fluentBitSet.shiftLeft(64, 128));

    }

    public static void providerAlgorithms() {
        GaloisJCE.add();
        for (Provider provider : Security.getProviders()) {
            System.out.printf("Provider: %s v%s%n", provider.getName(), provider.getVersionStr());
            System.out.println(provider.getInfo());
            for (Provider.Service service : provider.getServices()) {
                System.out.printf("  %s: %s%n", service.getType(), service.getAlgorithm());
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

    public static void reverseBits() {
        byte[] b = new byte[44];
        new Random().nextBytes(b);

        byte[] bClone = b.clone();
        byte[] reverse = new byte[bClone.length];

        for (int i = 0; i < bClone.length * 8; i++) {
            int index = i / 8;
            reverse[reverse.length - index - 1] <<= 1;
            reverse[reverse.length - index - 1] |= bClone[index] & 0x1;
            bClone[index] >>= 1;
        }

        bClone = b.clone();
        reverse = new byte[bClone.length];
        for (int j = 0; j < bClone.length; j++) {
            for (int i = 0; i < 8; i++) {
                reverse[reverse.length - j - 1] <<= 1;
                reverse[reverse.length - j - 1] |= (bClone[j]) & 0x1;
                bClone[j] >>= 1;
            }
        }
        System.out.println(Arrays.equals(bClone, b));

        for (int i = 0; i < bClone.length * 8; i++) {
            int index = i / 8;
            int remainder = i % 8;
            if ((reverse[reverse.length - index - 1] >> (remainder) & 1) != (b[index] >> (7 - remainder) & 1)) {
                System.out.println("Error");
                return;
            }
        }
        System.out.println("OK");

    }
}

