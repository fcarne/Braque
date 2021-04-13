package crypto;

import org.reflections.Reflections;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.*;

public class GaloisJCE extends Provider {


    private static final String info = "Galois Provider " +
            "(implements FastOPE, PIOre,  CommonDivisor, TYM, Crypto-PAN - David Stott's implementation, ESAE HPCBC+ )";


    // Instance of this provider, so we don't have to call the provider list
    // to find ourselves or run the risk of not being in the list.
    private static volatile GaloisJCE instance = null;

    // lazy initialize SecureRandom to avoid potential recursion if Sun
    // provider has not been installed yet
    private static class SecureRandomHolder {
        static final SecureRandom RANDOM = new SecureRandom();
    }

    public static SecureRandom getRandom() {
        return SecureRandomHolder.RANDOM;
    }

    public GaloisJCE() {
        super("GaloisJCE", "1.0", info);

        autoBind(GaloisJCE.class.getPackageName());


        if (instance == null) {
            instance = this;
        }
    }

    public void autoBind(String packageName) {
        new Reflections(packageName).getSubTypesOf(EngineAutoBindable.class).forEach(autoBindable -> {
            try {
                Method getBind = EngineAutoBindable.getBindMethod();
                if (!(Modifier.isAbstract(autoBindable.getModifiers()) || autoBindable.isInterface())) {
                    Object obj = autoBindable.getDeclaredConstructor().newInstance();
                    put(getBind.invoke(obj), autoBindable.getName());
                }
            } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException | InstantiationException e) {
                e.printStackTrace();
            }
        });
    }

    // Return the instance of this class or create one if needed.
    public static GaloisJCE getInstance() {
        if (instance == null) {
            return new GaloisJCE();
        }
        return instance;
    }

    public static void add() {
        Security.addProvider(getInstance());
    }

}
