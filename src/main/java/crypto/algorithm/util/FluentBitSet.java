package crypto.algorithm.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.BitSet;

public class FluentBitSet implements Cloneable {

    private BitSet bitset;

    public FluentBitSet() {
        bitset = new BitSet();
    }

    public FluentBitSet(int nbits) {
        bitset = new BitSet(nbits);
    }

    private FluentBitSet(BitSet bitset) {
        this.bitset = (BitSet) bitset.clone();
    }

    public static FluentBitSet valueOf(ByteBuffer buffer, ByteOrder order) {
        if (ByteOrder.LITTLE_ENDIAN.equals(order))
            return new FluentBitSet(BitSet.valueOf(buffer));

        if (ByteOrder.BIG_ENDIAN.equals(order)) {
            buffer = buffer.duplicate();

            int n = buffer.capacity();
            long[] words = new long[(n + 7) / 8];

            int i = 0;
            while (n >= 8) {
                words[i++] = buffer.getLong(n - 8);
                n -= 8;
            }

            for (int j = n; j > 0; j--) words[i] |= (buffer.get(j - 1) & 0xFFL) << ((n - j) * 8);

            return new FluentBitSet(BitSet.valueOf(words));
        }

        throw new RuntimeException("Invalid value for ByteOrder: " + order.toString());
    }

    public static FluentBitSet valueOf(ByteBuffer buffer) {
        return valueOf(buffer, ByteOrder.LITTLE_ENDIAN);
    }

    public static FluentBitSet valueOf(byte[] bytes, ByteOrder order) {
        return valueOf(ByteBuffer.wrap(bytes), order);
    }

    public static FluentBitSet valueOf(byte[] bytes) {
        return valueOf(bytes, ByteOrder.LITTLE_ENDIAN);
    }

    public static FluentBitSet valueOf(BitSet bitSet) {
        return new FluentBitSet(bitSet);
    }

    public BitSet getBitset() {
        return bitset;
    }

    public FluentBitSet get(int bitIndex) {
        FluentBitSet newBitSet = new FluentBitSet();
        newBitSet.bitset.set(bitIndex, this.bitset.get(bitIndex));
        return newBitSet;
    }

    public FluentBitSet set(int fromIndex, int toIndex) {
        bitset.set(fromIndex, toIndex);
        return this;
    }

    public FluentBitSet and(BitSet set) {
        bitset.and(set);
        return this;
    }

    public FluentBitSet and(FluentBitSet fluentBitSet) {
        return and(fluentBitSet.bitset);
    }

    public FluentBitSet or(BitSet set) {
        bitset.or(set);
        return this;
    }

    public FluentBitSet or(FluentBitSet fluentBitSet) {
        return or(fluentBitSet.bitset);
    }

    public FluentBitSet xor(BitSet set) {
        bitset.xor(set);
        return this;
    }

    public FluentBitSet xor(FluentBitSet fluentBitSet) {
        return xor(fluentBitSet.bitset);
    }

    public FluentBitSet shiftLeft(int n, int maxBitSize) throws IllegalArgumentException {
        if (maxBitSize % 64 != 0) throw new IllegalArgumentException("maxBitSize must be a multiple of 64");
        return shiftLeft(n, bitset.toLongArray(), maxBitSize / 64);
    }

    public FluentBitSet shiftLeft(int n) {
        long[] words = bitset.toLongArray();
        return shiftLeft(n, words, words.length);
    }

    private FluentBitSet shiftLeft(int n, long[] words, int length) {
        long[] shifted = new long[length];

        int leftPart = n / 64;
        int rightPart = leftPart + 1;

        for (int i = shifted.length - 1; i >= 0; i--) {
            if (i - rightPart >= words.length) continue;
            if (n % 64 != 0 && i > rightPart - 1) {
                shifted[i] |= words[i - rightPart] >>> (64 - n % 64);
            }
            if (i - leftPart >= words.length) continue;
            if (i > leftPart - 1)
                shifted[i] |= words[i - leftPart] << n;

        }
        bitset = BitSet.valueOf(shifted);
        return this;
    }

    public FluentBitSet shiftRight(int n) {
        long[] words = bitset.toLongArray();
        long[] shifted = new long[words.length];

        int rightPart = n / 64;
        int leftPart = rightPart + 1;

        for (int i = 0; i < words.length; i++) {
            if (i < words.length - rightPart) {
                shifted[i] |= words[i + rightPart] >>> n;
            }
            if (n % 64 != 0 && i < words.length - leftPart) {
                shifted[i] |= words[i + leftPart] << (64 - n % 64);
            }
        }
        bitset = BitSet.valueOf(shifted);
        return this;
    }

    public byte[] toByteArray(ByteOrder order) {
        if (ByteOrder.LITTLE_ENDIAN.equals(order))
            return bitset.toByteArray();

        if (ByteOrder.BIG_ENDIAN.equals(order)) {
            long[] words = bitset.toLongArray();
            int n = words.length;

            if (n == 0) return new byte[0];

            int len = 8 * (n - 1);
            int singleBytes = 0;
            for (long x = words[n - 1]; x != 0; x >>>= 8) singleBytes++;
            len += singleBytes;

            byte[] bytes = new byte[len];
            ByteBuffer buffer = ByteBuffer.wrap(bytes);

            for (int j = singleBytes - 1; j >= 0; j--) buffer.put((byte) (words[n - 1] >>> j * 8 & 0xFF));

            for (int i = n - 2; i >= 0; i--) buffer.putLong(words[i]);

            return bytes;
        }

        throw new RuntimeException("Invalid value for ByteOrder: " + order.toString());
    }

    public byte[] toByteArray() {
        return toByteArray(ByteOrder.LITTLE_ENDIAN);
    }

    public static byte[] reverseBytes(byte[] input) {
        byte[] reversed = input.clone();
        for (int i = 0; i < reversed.length / 2; i++) {
            byte temp = reversed[i];
            reversed[i] = reversed[reversed.length - 1 - i];
            reversed[reversed.length - 1 - i] = temp;
        }
        return reversed;
    }

    @Override
    public String toString() {
        return bitset.toString();
    }
}
