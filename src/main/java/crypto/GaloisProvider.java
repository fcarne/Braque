package crypto;

import org.reflections.Reflections;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.Provider;
import java.security.Security;

public class GaloisProvider extends Provider {
    public static final String NAME = "Galois Custom Provider";

    public GaloisProvider() {
        super(NAME, "1.0", "Galois provider v1.0");

        autoBind(this.getClass().getPackageName());
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

    public static void add() {
        Security.addProvider(new GaloisProvider());
    }

    public static GaloisProvider get() {
        return (GaloisProvider) Security.getProvider(NAME);
    }
}
