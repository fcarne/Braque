package crypto;

import org.reflections.Reflections;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;

public class BraqueProvider extends Provider {
    public static final String NAME = "Braque Custom Provider";

    public BraqueProvider() {
        super(NAME, "1.0", "Braque provider v1.0");

        autoBind(this.getClass().getPackageName());
    }

    public void autoBind(String packageName) {
        new Reflections(packageName).getSubTypesOf(EngineAutoBindable.class).forEach(autoBindable -> {
            try {
                Method getBind = autoBindable.getMethod(EngineAutoBindable.BIND_METHOD);
                Object obj = autoBindable.getDeclaredConstructor().newInstance();
                put(getBind.invoke(obj), autoBindable.getCanonicalName());
            } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException | InstantiationException e) {
                e.printStackTrace();
            }
        });
    }

    public static void add() {
        Security.addProvider(new BraqueProvider());
    }

    public static BraqueProvider get() {
        return (BraqueProvider) Security.getProvider(NAME);
    }
}
