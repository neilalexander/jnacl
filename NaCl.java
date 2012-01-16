package com.neilalexander.jnacl;

import java.util.Formatter;

import com.neilalexander.jnacl.crypto.*;

public class NaCl
{
	static final int crypto_secretbox_KEYBYTES = 32;
	static final int crypto_secretbox_NONCEBYTES = 24;
	static final int crypto_secretbox_ZEROBYTES = 32;
	static final int crypto_secretbox_BOXZEROBYTES = 16;
	static final int crypto_secretbox_BEFORENMBYTES = 32;
	
	private byte[] precomputed = new byte[crypto_secretbox_BEFORENMBYTES];
	
	public NaCl(byte[] privatekey, byte[] publickey) throws Exception
	{
		if (privatekey.length < crypto_secretbox_KEYBYTES)
			throw new Exception("Private key too short");
		
		if (publickey.length < crypto_secretbox_KEYBYTES)
			throw new Exception("Public key too short");
		
		curve25519xsalsa20poly1305.crypto_box_beforenm(this.precomputed, publickey, privatekey);
		//System.out.println("int1: " + asHex(this.precomputed));
		//this.precomputed = getBinary("74af7e9b705bdb51a512c9c915dd79779abc3ec86d0e099c0242b52a28749e83");
		//System.out.println("int2: " + asHex(this.precomputed));
	}
	
	public NaCl(String privatekey, String publickey) throws Exception
	{				
		if (privatekey.length() < crypto_secretbox_KEYBYTES * 2)
			throw new Exception("Private key too short");
		
		if (publickey.length() < crypto_secretbox_KEYBYTES * 2)
			throw new Exception("Public key too short");
		
		curve25519xsalsa20poly1305.crypto_box_beforenm(this.precomputed, getBinary(publickey), getBinary(privatekey));
		//System.out.println("int1: " + asHex(this.precomputed));
		//this.precomputed = getBinary("74af7e9b705bdb51a512c9c915dd79779abc3ec86d0e099c0242b52a28749e83");
		//System.out.println("int2: " + asHex(this.precomputed));
	}
	
	public byte[] encrypt(byte[] input, byte[] nonce)
	{
		byte[] paddedinput = new byte[input.length + crypto_secretbox_ZEROBYTES];
		byte[] output = new byte[input.length + crypto_secretbox_ZEROBYTES];
		
		System.arraycopy(input, 0, paddedinput, crypto_secretbox_ZEROBYTES, input.length);
		curve25519xsalsa20poly1305.crypto_box_afternm(output, paddedinput, paddedinput.length, nonce, this.precomputed);
		
		return output;
	}
	
	public byte[] encrypt(byte[] input, int inputlength, byte[] nonce)
	{
		byte[] paddedinput = new byte[inputlength + crypto_secretbox_ZEROBYTES];
		byte[] output = new byte[inputlength + crypto_secretbox_ZEROBYTES];
		
		System.arraycopy(input, 0, paddedinput, crypto_secretbox_ZEROBYTES, inputlength);
		curve25519xsalsa20poly1305.crypto_box_afternm(output, paddedinput, paddedinput.length, nonce, this.precomputed);
		
		return output;
	}
	
	public byte[] decrypt(byte[] input, byte[] nonce)
	{
		byte[] paddedoutput = new byte[input.length];
		byte[] output = new byte[input.length - crypto_secretbox_ZEROBYTES];
		
		curve25519xsalsa20poly1305.crypto_box_afternm(paddedoutput, input, input.length, nonce, this.precomputed);
		System.arraycopy(paddedoutput, crypto_secretbox_ZEROBYTES, output, 0, paddedoutput.length - crypto_secretbox_ZEROBYTES);
		
		return output;
	}
	
	public byte[] decrypt(byte[] input, int inputlength, byte[] nonce)
	{
		byte[] paddedoutput = new byte[inputlength];
		byte[] output = new byte[inputlength - crypto_secretbox_ZEROBYTES];
		
		curve25519xsalsa20poly1305.crypto_box_afternm(paddedoutput, input, inputlength, nonce, this.precomputed);
		System.arraycopy(paddedoutput, crypto_secretbox_ZEROBYTES, output, 0, paddedoutput.length - crypto_secretbox_ZEROBYTES);
		
		return output;
	}
	
	public static byte[] getBinary(String s)
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
	
	public static String asHex(byte[] buf)
	{
		Formatter formatter = new Formatter();
		for (byte b : buf)
			formatter.format("%02x", b);
		return formatter.toString();
	}
}
