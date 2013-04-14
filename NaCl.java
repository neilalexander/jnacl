//
//  Copyright (c) 2011, Neil Alexander T.
//  All rights reserved.
// 
//  Redistribution and use in source and binary forms, with
//  or without modification, are permitted provided that the following
//  conditions are met:
// 
//  - Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  - Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//

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
	
	public NaCl(byte[] privatekey, byte[] publickey)
	{
		curve25519xsalsa20poly1305.crypto_box_beforenm(this.precomputed, publickey, privatekey);
	}
	
	public NaCl(String privatekey, String publickey) throws Exception
	{			
		this(getBinary(privatekey), getBinary(publickey));
	}
	
	public byte[] encrypt(byte[] input, byte[] nonce)
	{
		return encrypt(input, 0, input.length, nonce);
	}
	
	public byte[] encrypt(byte[] input, int inputlength, byte[] nonce)
	{
		return encrypt(input, 0, inputlength, nonce);
	}
	
	public byte[] encrypt(byte[] input, int inputoffset, int inputlength, byte[] nonce)
	{
		byte[] paddedbuffer = new byte[inputlength + crypto_secretbox_ZEROBYTES];
		System.arraycopy(input, inputoffset, paddedbuffer, crypto_secretbox_ZEROBYTES, inputlength);
		curve25519xsalsa20poly1305.crypto_box_afternm(paddedbuffer, paddedbuffer, paddedbuffer.length, nonce, this.precomputed);
		byte[] output = new byte[inputlength + crypto_secretbox_BOXZEROBYTES];
		System.arraycopy(paddedbuffer, crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES, output, 0, output.length);
		return output;
	}
	
	public byte[] decrypt(byte[] input, byte[] nonce)
	{
		return decrypt(input, 0, input.length, nonce);
	}
	
	public byte[] decrypt(byte[] input, int inputlength, byte[] nonce)
	{
		return decrypt(input, 0, inputlength, nonce);
	}
	
	public byte[] decrypt(byte[] input, int inputoffset, int inputlength, byte[] nonce)
	{
		byte[] paddedbuffer = new byte[inputlength + crypto_secretbox_BOXZEROBYTES];
		System.arraycopy(input, inputoffset, paddedbuffer, crypto_secretbox_BOXZEROBYTES, inputlength);
		if (curve25519xsalsa20poly1305.crypto_box_afternm(paddedbuffer, paddedbuffer, paddedbuffer.length, nonce, this.precomputed) != 0)
			throw new SecurityException("Decryption failed");
		byte[] output = new byte[paddedbuffer.length - crypto_secretbox_ZEROBYTES];
		System.arraycopy(paddedbuffer, crypto_secretbox_ZEROBYTES, output, 0, output.length);
		return output;
	}
	
	public static byte[] getBinary(String s)
	{
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    
	    for (int i = 0; i < len; i += 2)
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
	    
	    return data;
	}
	
	public static String asHex(byte[] buf)
	{
		Formatter formatter = new Formatter();
		for (byte b : buf)
			formatter.format("%02x", b);
		return formatter.toString();
	}
	
	public static String asHex(int[] buf)
	{
		Formatter formatter = new Formatter();
		for (int b : buf)
			formatter.format("%02x", b);
		return formatter.toString();
	}
}
