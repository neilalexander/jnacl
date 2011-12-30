package jnacl;

import jnacl.crypto.curve25519xsalsa20poly1305;

public class NaCl
{
	static final int crypto_secretbox_KEYBYTES = 32;
	static final int crypto_secretbox_NONCEBYTES = 24;
	static final int crypto_secretbox_ZEROBYTES = 32;
	static final int crypto_secretbox_BOXZEROBYTES = 16;
	
	private byte[] privatekey = new byte[crypto_secretbox_KEYBYTES];
	private byte[] publickey = new byte[crypto_secretbox_KEYBYTES];
	
	public NaCl(byte[] privatekey, byte[] publickey) throws Exception
	{
		if (privatekey.length < crypto_secretbox_KEYBYTES)
			throw new Exception("Private key too short");
		
		if (publickey.length < crypto_secretbox_KEYBYTES)
			throw new Exception("Public key too short");
		
		this.privatekey = privatekey;
		this.publickey = publickey;
	}
	
	public NaCl(String privatekey, String publickey) throws Exception
	{				
		if (privatekey.length() < crypto_secretbox_KEYBYTES * 2)
			throw new Exception("Private key too short");
		
		if (publickey.length() < crypto_secretbox_KEYBYTES * 2)
			throw new Exception("Public key too short");
		
		this.privatekey = getBinary(privatekey);
		this.publickey = getBinary(publickey);
	}
	
	public byte[] encrypt(byte[] input, byte[] nonce)
	{
		byte[] paddedinput = new byte[input.length + crypto_secretbox_ZEROBYTES];
		byte[] output = new byte[input.length + crypto_secretbox_ZEROBYTES];
		
		System.arraycopy(input, 0, paddedinput, crypto_secretbox_ZEROBYTES, input.length);
		curve25519xsalsa20poly1305.crypto_box(output, paddedinput, paddedinput.length, nonce, this.publickey, this.privatekey);
		
		return output;
	}
	
	public byte[] decrypt(byte[] input, byte[] nonce)
	{
		byte[] paddedoutput = new byte[input.length];
		byte[] output = new byte[input.length - crypto_secretbox_ZEROBYTES];
		
		curve25519xsalsa20poly1305.crypto_box(paddedoutput, input, input.length, nonce, this.publickey, this.privatekey);
		System.arraycopy(paddedoutput, crypto_secretbox_ZEROBYTES, output, 0, paddedoutput.length - crypto_secretbox_ZEROBYTES);
		
		return output;
	}
	
	private static byte[] getBinary(String s)
	{
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    
	    for (int i = 0; i < len; i += 2)
	    {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                              + Character.digit(s.charAt(i+1), 16));
	    }
	    
	    return data;
	}
}
