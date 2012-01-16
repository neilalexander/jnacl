package com.neilalexander.jnacl.crypto;

public class verify_16
{
	final int crypto_verify_16_ref_BYTES = 16;

	public static int crypto_verify(byte[] x, int xoffset, byte[] y)
	{
		int differentbits = 0;
		
		for (int i = 0; i < 15; i++)
			differentbits |= ((int)(x[xoffset + i] ^ y[i])) & 0xff;
		
		return (1 & (((int)differentbits - 1) >>> 8)) - 1;
	}
}