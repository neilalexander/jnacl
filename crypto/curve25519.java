package jnacl.crypto;

public class curve25519
{
	final int CRYPTO_BYTES = 32;
	final int CRYPTO_SCALARBYTES = 32;
	
	static byte[] basev = { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	static long[] minusp = { 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128 };

	public static int crypto_scalarmult_base(byte[] q, byte[] n)
	{
		byte[] basevp = basev;
		return crypto_scalarmult(q, n, basevp);
	}
	
	static void add(long[] outv, int outvoffset, long[] a, int aoffset, long[] b, int boffset)
	{
		long u = 0;
		
		for (int j = 0; j < 31; ++j)
		{
			u += a[aoffset + j] + b[boffset + j];
			outv[outvoffset + j] = u & 255; u = (u & 0xFFFFFFFF) >> 8;
		}
		
		u += a[aoffset + 31] + b[boffset + 31];
		outv[outvoffset + 31] = u;
	}

	static void sub(long[] outv, int outvoffset, long[] a, int aoffset, long[] b, int boffset)
	{
		long u = 218;
		
		for (int j = 0; j < 31; ++j)
		{
			u += a[aoffset + j] + 65280 - b[boffset + j];
			outv[outvoffset + j] = u & 255;
			u = (u & 0xFFFFFFFF) >> 8;
		}
		
		u += a[aoffset + 31] - b[boffset + 31];
		outv[outvoffset + 31] = u;
	}

	static void squeeze(long[] a, int aoffset)
	{
		long u = 0;
		
		for (int j = 0; j < 31; ++j)
		{
			u += a[aoffset + j];
			a[aoffset + j] = u & 255;
			u = (u & 0xFFFFFFFF) >> 8;
		}
		
		u += a[aoffset + 31];
		a[aoffset + 31] = u & 127;
		u = 19 * (u >> 7);
		
		for (int j = 0; j < 31; ++j)
		{
			u += a[aoffset + j];
			a[aoffset + j] = u & 255;
			u = (u & 0xFFFFFFFF) >> 8;
		}
		
		u += a[aoffset + 31];
		a[aoffset + 31] = u;
	}

	static void freeze(long[] a, int aoffset)
	{
		long[] aorig = new long[32];
		
		for (int j = 0; j < 32; ++j)
			aorig[j] = a[aoffset + j];
		
		long[] minuspp = minusp;
		
		add(a, 0, a, 0, minuspp, 0);
		
		long negative = (long) (-((a[aoffset + 31] >> 7) & 1));
		negative &= 0xFFFFFFFF;
		
		for (int j = 0; j < 32; ++j)
			a[aoffset + j] ^= negative & (aorig[j] ^ a[aoffset + j]);
	}

	static void mult(long[] outv, int outvoffset, long[] a, int aoffset, long[] b, int boffset)
	{
		int j;
		
		for (int i = 0; i < 32; ++i)
		{
			long u = 0;
			
			for (j = 0; j <= i; ++j)
				u += a[aoffset + j] * b[boffset + i - j];
			
			for (j = i + 1; j < 32; ++j)
				u += 38 * a[aoffset + j] * b[boffset + i + 32 - j];
			
			outv[outvoffset + i] = u & 0xFFFFFFFF;
		}
		
		squeeze(outv, outvoffset);
	}

	static void mult121665(long[] outv, long[] a)
	{
		int j;
		long u = 0;
		
		for (j = 0; j < 31; ++j)
		{
			u += 121665 * a[j];
			outv[j] = u & 255;
			u = (u & 0xFFFFFFFF) >> 8;
		}
		
		u += 121665 * a[31];
		outv[31] = u & 127;
		u = 19 * ((u & 0xFFFFFFFF) >> 7);
		
		for (j = 0; j < 31; ++j)
		{
			u += outv[j];
			outv[j] = u & 255;
			u = (u & 0xFFFFFFFF) >> 8;
		}
		
		u += outv[j];
		outv[j] = u & 0xFFFFFFFF;
	}
	
	static void square(long[] outv, int outvoffset, long[] a, int aoffset)
	{
		int j;
		
		for (int i = 0; i < 32; ++i)
		{
			long u = 0;
			
			for (j = 0; j < i - j; ++j)
				u += a[aoffset + j] * a[aoffset + i - j];
			
			for (j = i + 1; j < i + 32 - j; ++j)
				u += 38 * a[aoffset + j] * a[aoffset + i + 32 - j];
			
			u *= 2;
			
			if ((i & 1) == 0)
			{
				u += a[aoffset + i / 2] * a[aoffset + i / 2];
				u += 38 * a[aoffset + i / 2 + 16] * a[aoffset + i / 2 + 16];
			}
			
			outv[outvoffset + i] = u & 0xFFFFFFFF;
		}
		
		squeeze(outv, outvoffset);
	}

	static void select(long[] p, long[] q, long[] r, long[] s, long b)
	{
		long bminus1 = b - 1;
		
		for (int j = 0; j < 64; ++j)
		{
			long t = bminus1 & (r[j] ^ s[j]);
			p[j] = s[j] ^ t;
			q[j] = r[j] ^ t;
		}
	}

	static void mainloop(long[] work, byte[] e)
	{
		long[] xzm1 = new long[64];
		long[] xzm = new long[64];
		long[] xzmb = new long[64];
		long[] xzm1b = new long[64];
		long[] xznb = new long[64];
		long[] xzn1b = new long[64];
		long[] a0 = new long[64];
		long[] a1 = new long[64];
		long[] b0 = new long[64];
		long[] b1 = new long[64];
		long[] c1 = new long[64];
		long[] r = new long[32];
		long[] s = new long[32];
		long[] t = new long[32];
		long[] u = new long[32];

		for (int j = 0; j < 32; ++j)
			xzm1[j] = work[j];
		
		xzm1[32] = 1;
		
		for (int j = 33; j < 64; ++j)
			xzm1[j] = 0;

		xzm[0] = 1;
		
		for (int j = 1; j < 64; ++j)
			xzm[j] = 0;

		long[] xzmbp = xzmb, a0p = a0, xzm1bp = xzm1b;
		long[] a1p = a1, b0p = b0, b1p = b1, c1p = c1;
		long[] xznbp = xznb, up = u, xzn1bp = xzn1b;
		long[] workp = work, sp = s, rp = r;

		for (int pos = 254; pos >= 0; --pos)
		{
			long b = ((long) (e[pos / 8] >> (pos & 7))) & 0xffffffff;
			b &= 1;
			select(xzmb, xzm1b, xzm, xzm1, b);
			add(a0, 	0,	xzmb, 	0,	xzmbp,	32);
			sub(a0p,	32,	xzmb, 	0,	xzmbp, 	32);
			add(a1, 	0,	xzm1b, 	0,	xzm1bp,	32);
			sub(a1p,	32,	xzm1b, 	0,	xzm1bp, 32);
			square(b0p,	0,	a0p,	0);
			square(b0p, 32,	a0p,	32);
			mult(b1p,	0,	a1p,	0, 	a0p,	32);
			mult(b1p,	32,	a1p,	32,	a0p,	0);
			add(c1, 	0,	b1, 	0,	b1p,	32);
			sub(c1p,	32,	b1,		0,	b1p,	32);
			square(rp,	0,	c1p,	32);
			sub(sp,		0,	b0,		0,	b0p,	32);
			mult121665(t, s);
			add(u, 		0,	t, 		0,	b0p,	0);
			mult(xznbp,	0,	b0p,	0,	b0p,	32);
			mult(xznbp,	32, sp,		0,	up,		0);
			square(xzn1bp, 0, c1p,	0);
			mult(xzn1bp, 32, rp, 	0, 	workp, 	0);
			select(xzm, xzm1, xznb, xzn1b, b);
		}

		for (int j = 0; j < 64; ++j)
			work[j] = xzm[j];
	}

	static void recip(long[] outv, int outvoffset, long[] z, int zoffset)
	{
		long[] z2 = new long[32];
		long[] z9 = new long[32];
		long[] z11 = new long[32];
		long[] z2_5_0 = new long[32];
		long[] z2_10_0 = new long[32];
		long[] z2_20_0 = new long[32];
		long[] z2_50_0 = new long[32];
		long[] z2_100_0 = new long[32];
		long[] t0 = new long[32];
		long[] t1 = new long[32];

		/* 2 */
		long[] z2p = z2;
		square(z2p, 0, z, zoffset);
		
		/* 4 */
		square(t1, 0, z2, 0);
		
		/* 8 */
		square(t0, 0, t1, 0);
		
		/* 9 */
		long[] z9p = z9, t0p = t0;
		mult(z9p, 0, t0p, 0, z, zoffset);
		
		/* 11 */
		mult(z11, 0, z9, 0, z2, 0);
		
		/* 22 */
		square(t0, 0, z11, 0);
		
		/* 2^5 - 2^0 = 31 */
		mult(z2_5_0, 0, t0, 0, z9, 0);

		/* 2^6 - 2^1 */
		square(t0, 0, z2_5_0, 0);
		
		/* 2^7 - 2^2 */
		square(t1, 0, t0, 0);
		
		/* 2^8 - 2^3 */
		square(t0, 0, t1, 0);
		
		/* 2^9 - 2^4 */
		square(t1, 0, t0, 0);
		
		/* 2^10 - 2^5 */
		square(t0, 0, t1, 0);
		
		/* 2^10 - 2^0 */
		mult(z2_10_0, 0, t0, 0, z2_5_0, 0);

		/* 2^11 - 2^1 */
		square(t0, 0, z2_10_0, 0);
		
		/* 2^12 - 2^2 */
		square(t1, 0, t0, 0);
		
		/* 2^20 - 2^10 */
		for (int i = 2; i < 10; i += 2)
		{ 
			square(t0, 0, t1, 0);
			square(t1, 0, t0, 0);
		}
		
		/* 2^20 - 2^0 */
		mult(z2_20_0, 0, t1, 0, z2_10_0, 0);

		/* 2^21 - 2^1 */
		square(t0, 0, z2_20_0, 0);
		
		/* 2^22 - 2^2 */
		square(t1, 0, t0, 0);
		
		/* 2^40 - 2^20 */
		for (int i = 2; i < 20; i += 2) 
		{ 
			square(t0, 0, t1, 0); 
			square(t1, 0, t0, 0); 
		}
		
		/* 2^40 - 2^0 */
		mult(t0, 0, t1, 0, z2_20_0, 0);

		/* 2^41 - 2^1 */
		square(t1, 0, t0, 0);
		
		/* 2^42 - 2^2 */
		square(t0, 0, t1, 0);
		
		/* 2^50 - 2^10 */
		for (int i = 2; i < 10; i += 2) 
		{ 
			square(t1, 0, t0, 0); 
			square(t0, 0, t1, 0); 
		}
		
		/* 2^50 - 2^0 */
		mult(z2_50_0, 0, t0, 0, z2_10_0, 0);

		/* 2^51 - 2^1 */
		square(t0, 0, z2_50_0, 0);
		
		/* 2^52 - 2^2 */
		square(t1, 0, t0, 0);
		
		/* 2^100 - 2^50 */
		for (int i = 2; i < 50; i += 2)
		{ 
			square(t0, 0, t1, 0); 
			square(t1, 0, t0, 0); 
		}
		
		/* 2^100 - 2^0 */
		mult(z2_100_0, 0, t1, 0, z2_50_0, 0);

		/* 2^101 - 2^1 */
		square(t1, 0, z2_100_0, 0);
		
		/* 2^102 - 2^2 */
		square(t0, 0, t1, 0);
		
		/* 2^200 - 2^100 */
		for (int i = 2; i < 100; i += 2)
		{
			square(t1, 0, t0, 0);
			square(t0, 0, t1, 0);
		}
		
		/* 2^200 - 2^0 */
		mult(t1, 0, t0, 0, z2_100_0, 0);

		/* 2^201 - 2^1 */
		square(t0, 0, t1, 0);
		
		/* 2^202 - 2^2 */
		square(t1, 0, t0, 0);
		
		/* 2^250 - 2^50 */
		for (int i = 2; i < 50; i += 2)
		{
			square(t0, 0, t1, 0);
			square(t1, 0, t0, 0);
		}
		
		/* 2^250 - 2^0 */
		mult(t0, 0, t1, 0, z2_50_0, 0);

		/* 2^251 - 2^1 */
		square(t1, 0, t0, 0);
		
		/* 2^252 - 2^2 */
		square(t0, 0, t1, 0);
		
		/* 2^253 - 2^3 */
		square(t1, 0, t0, 0);
		
		/* 2^254 - 2^4 */
		square(t0, 0, t1, 0);
		
		/* 2^255 - 2^5 */
		square(t1, 0, t0, 0);
		
		/* 2^255 - 21 */
		long[] t1p = t1, z11p = z11;
		mult(outv, outvoffset, t1p, 0, z11p, 0);
	}

	public static int crypto_scalarmult(byte[] q, byte[] n, byte[] p)
	{
		long[] work = new long[96];
		byte[] e = new byte[32];
		
		for (int i = 0; i < 32; ++i)
			e[i] = n[i];
		
		e[0] &= 248;
		e[31] &= 127;
		e[31] |= 64;
		
		for (int i = 0; i < 32; ++i)
			work[i] = p[i];
		
		mainloop(work, e);
		
		long[] workp = work;
		recip(workp, 32, workp, 32);
		mult(workp, 64, workp, 0, workp, 32);
		freeze(workp, 64);
		
		for (int i = 0; i < 32; ++i)
			q[i] = (byte) work[64 + i];
		
		return 0;
	}
}