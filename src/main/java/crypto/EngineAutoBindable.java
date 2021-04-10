package crypto;

import java.lang.reflect.Method;

public interface EngineAutoBindable {

    static Method getBindMethod() throws NoSuchMethodException {
        return EngineAutoBindable.class.getMethod("getBind");
    }

    String getBind();

}
