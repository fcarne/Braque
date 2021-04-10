package util;

import java.nio.ByteBuffer;
import java.util.BitSet;

public class BitSetUtils {

    public static BitSet shiftLeft(BitSet bitSet, int n) {
        long[] words = bitSet.toLongArray();

        for (int i = words.length - 1; i >= 0; i--) {
            words[i] <<= n;
            if (i != 0) {
                words[i] |= words[i - 1] >>> (64 - n);
            }
        }

        return BitSet.valueOf(words);

    }

    public static BitSet shiftRight(BitSet bitSet, int n) {
        long[] words = bitSet.toLongArray();
        for (int i = 0; i < words.length; i++) {
            words[i] >>>= n;
            if (i != words.length - 1) {
                words[i] |= words[i + 1] << (64 - n);
            }
        }
        return BitSet.valueOf(words);
    }

    public static BitSet valueOf(long l) {
        return BitSet.valueOf(new long[]{l});
    }

    public static BitSet fromBigEndian(byte[] bytes) {
        return BitSet.valueOf(reverseBytes(bytes));
    }

    public static BitSet fromBigEndian(ByteBuffer buffer) {
        return fromBigEndian(buffer.array());
    }

    public static byte[] toBigEndian(BitSet bitSet) {
        return reverseBytes(bitSet.toByteArray());
    }

    private static byte[] reverseBytes(byte[] input) {
        byte[] reversed = input.clone();
        for (int i = 0; i < reversed.length / 2; i++) {
            byte temp = reversed[i];
            reversed[i] = reversed[reversed.length - 1 - i];
            reversed[reversed.length - 1 - i] = temp;
        }
        return reversed;
    }

}
