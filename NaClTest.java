package jnacl;

import java.util.Formatter;

public class NaClTest
{
	private static String privatekey = "e8bdd098b2d6b595e574bd935f47678bde87e38e06e8ca4c4c9d8ead283b49ee";
	private static String publickey = "0d8b0aaf5747a5465696d0c8ffe98372ff0af5f012a24c96b3f6033d8125f843";
	private static byte[] nonce = new byte[24];
	
	public static void main(String[] args) throws Exception
	{
		NaCl test = new NaCl(privatekey, publickey);
		byte[] in = "HELLO!".getBytes();
		
		byte[] foo = test.encrypt(in, nonce);
		byte[] bar = test.decrypt(foo, nonce);
		
		System.out.println("in:  " + new String(in));
		System.out.println("enc: " + asHex(foo));
		System.out.println("dec: " + new String(bar));
	}

	private static String asHex(byte[] buf)
	{
		Formatter formatter = new Formatter();
		for (byte b : buf)
			formatter.format("%02x", b);
		return formatter.toString();
	}
}
