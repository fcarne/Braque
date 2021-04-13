package crypto.algorithm.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.BitSet;

public class FluentBitSet implements Cloneable {

    private BitSet bitSet;

    public FluentBitSet() {
        bitSet = new BitSet();
    }

    public FluentBitSet(int nbits) {
        bitSet = new BitSet(nbits);
    }

    private FluentBitSet(BitSet bitSet) {
        this.bitSet = (BitSet) bitSet.clone();
    }

    public static FluentBitSet valueOf(byte[] bytes, ByteOrder order) {
        if (ByteOrder.LITTLE_ENDIAN.equals(order))
            return new FluentBitSet(BitSet.valueOf(bytes));
        if (ByteOrder.BIG_ENDIAN.equals(order))
            return new FluentBitSet(BitSet.valueOf(reverseBytes(bytes)));
        return new FluentBitSet();
    }

    public static FluentBitSet valueOf(byte[] bytes) {
        return valueOf(bytes, ByteOrder.LITTLE_ENDIAN);
    }

    public static FluentBitSet valueOf(ByteBuffer buffer, ByteOrder order) {
        return valueOf(buffer.array(), order);
    }

    public static FluentBitSet valueOf(ByteBuffer buffer) {
        return valueOf(buffer.array());
    }

    public static FluentBitSet valueOf(BitSet bitSet) {
        return new FluentBitSet(bitSet);
    }

    public BitSet getBitSet() {
        return bitSet;
    }


    public FluentBitSet set(int fromIndex, int toIndex) {
        bitSet.set(fromIndex, toIndex);
        return this;
    }

    public FluentBitSet and(BitSet set) {
        bitSet.and(set);
        return this;
    }

    public FluentBitSet and(FluentBitSet fluentBitSet) {
        bitSet.and(fluentBitSet.bitSet);
        return this;
    }

    public FluentBitSet or(BitSet set) {
        bitSet.or(set);
        return this;
    }

    public FluentBitSet or(FluentBitSet fluentBitSet) {
        bitSet.or(fluentBitSet.bitSet);
        return this;
    }

    public FluentBitSet xor(BitSet set) {
        bitSet.xor(set);
        return this;
    }

    public FluentBitSet xor(FluentBitSet fluentBitSet) {
        bitSet.xor(fluentBitSet.bitSet);
        return this;
    }

    public FluentBitSet shiftLeft(int n) {
        long[] words = bitSet.toLongArray();
        for (int i = words.length - 1; i >= 0; i--) {
            words[i] <<= n;
            if (i != 0) {
                words[i] |= words[i - 1] >>> (64 - n);
            }
        }
        bitSet = BitSet.valueOf(words);
        return this;
    }

    public FluentBitSet shiftRight(int n) {
        long[] words = bitSet.toLongArray();
        for (int i = 0; i < words.length; i++) {
            words[i] >>>= n;
            if (i != words.length - 1) {
                words[i] |= words[i + 1] << (64 - n);
            }
        }
        bitSet = BitSet.valueOf(words);
        return this;
    }

    public byte[] toByteArray(ByteOrder order) {
        if (ByteOrder.LITTLE_ENDIAN.equals(order)) return bitSet.toByteArray();
        if (ByteOrder.BIG_ENDIAN.equals(order)) return reverseBytes(bitSet.toByteArray());
        return new byte[0];
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
}
