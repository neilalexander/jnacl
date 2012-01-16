package com.neilalexander.jnacl;

import java.util.Formatter;

public class NaClTest
{
	private static String publickey = "0cba66066896ffb51e92bc3c36ffa627c2493770d9b0b4368a2466c801b0184e";
	private static String privatekey = "176970653848be5242059e2308dfa30245b93a13befd2ebd09f09b971273b728";
	private static byte[] nonce = new byte[24];
	
	public static void main(String[] args) throws Exception
	{
		System.out.println(System.getProperty("java.version"));
		
		NaCl test = new NaCl(privatekey, publickey);
		byte[] in = "hi".getBytes();
		
		byte[] foo = test.encrypt(in, nonce);
		byte[] bar = test.decrypt(foo, nonce);
		
		System.out.println("in:  " + asHex(in));
		System.out.println("enc: " + asHex(foo));
		System.out.println("dec: " + asHex(bar));
		
		System.out.println("TEST: " + NaCl.asHex(test.encrypt("hi".getBytes(), new byte[24])));
	}

	public static String asHex(byte[] buf)
	{
		Formatter formatter = new Formatter();
		for (byte b : buf)
			formatter.format("%02x", b);
		return formatter.toString();
	}
}
