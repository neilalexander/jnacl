package com.neilalexander.jnacl;

import java.util.Random;

public class RandomBytes {
    static Random random = new Random();

    protected static byte random() {
        byte[] b = new byte[1];
        random.nextBytes(b);
        return b[0];
    }

    protected static void randombytes(byte[] bytes, int start, int end) {
        for (int i = start, len = bytes.length; i < end && i < len; )
            for (int rnd = random.nextInt(),
                 n = Math.min(len - i, Integer.SIZE / Byte.SIZE);
                 n-- > 0; rnd >>= Byte.SIZE)
                bytes[i++] = (byte) rnd;
    }
}
