package crypto;

import java.lang.reflect.Method;

public interface EngineAutoBindable {

    static Method getBindMethod() {
        try {
            return EngineAutoBindable.class.getMethod("getBind");
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
            return null;
        }
    }

    String getBind();

}
