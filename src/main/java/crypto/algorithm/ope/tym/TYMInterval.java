package crypto.algorithm.ope.tym;

import java.nio.ByteBuffer;

public class TYMInterval {
    public static final int BYTES = 2 * Integer.BYTES;
    public long c0;
    public long c1;

    public TYMInterval(long c0, long c1) {
        this.c0 = c0;
        this.c1 = c1;
    }

    public byte[] toByteArray() {
        return ByteBuffer.allocate(BYTES).putInt((int) c0).putInt((int) c1).array();
    }

    public static TYMInterval fromByteArray(byte[] array) {
        ByteBuffer buffer = ByteBuffer.wrap(array);
        return new TYMInterval(buffer.getInt(), buffer.getInt());
    }
}
