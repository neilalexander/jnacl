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

import java.security.SecureRandom;
import java.util.Formatter;

import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;
import com.neilalexander.jnacl.crypto.xsalsa20;
import com.neilalexander.jnacl.crypto.xsalsa20poly1305;

public class NaCl {
  public static final int PUBLICKEYBYTES = 32;
  public static final int SECRETKEYBYTES = 32;
  public static final int BEFORENMBYTES = 32;
  public static final int NONCEBYTES = 24;
  public static final int ZEROBYTES = 32;
  public static final int BOXZEROBYTES = 16;
  public static final int BOXOVERHEAD = ZEROBYTES - BOXZEROBYTES;
  public static final int SYMMKEYBYTES = 32;
  public static final int STREAMKEYBYTES = 32;

  private final byte[] precomputed = new byte[BEFORENMBYTES];

  public NaCl(byte[] privatekey, byte[] publickey) {
    if (privatekey.length != SECRETKEYBYTES) {
      throw new Error("Invalid private key length");
    }

    if (publickey.length != PUBLICKEYBYTES) {
      throw new Error("Invalid public key length");
    }

    curve25519xsalsa20poly1305.crypto_box_beforenm(this.precomputed, publickey, privatekey);
  }

  public NaCl(String privatekey, String publickey) {
    this(getBinary(privatekey), getBinary(publickey));
  }

  public byte[] encrypt(byte[] input, byte[] nonce) {
    return encrypt(input, input.length, nonce);
  }

  public byte[] encrypt(byte[] input, int inputlength, byte[] nonce) {
    if (nonce.length != NONCEBYTES) {
      throw new Error("Invalid nonce length");
    }

    byte[] output = new byte[inputlength + BOXOVERHEAD];
    curve25519xsalsa20poly1305.crypto_box_afternm_nopad(
        output, 0, input, 0, input.length, nonce, this.precomputed);

    return output;
  }

  public byte[] decrypt(byte[] input, byte[] nonce) {
    return decrypt(input, input.length, nonce);
  }

  public byte[] decrypt(byte[] input, int inputlength, byte[] nonce) {
    if (nonce.length != NONCEBYTES) {
      throw new Error("Invalid nonce length");
    }

    if (inputlength < BOXOVERHEAD) {
      return null;
    }

    byte[] output = new byte[inputlength - BOXOVERHEAD];
    if (curve25519xsalsa20poly1305.crypto_box_open_afternm_nopad(
            output, 0, input, 0, input.length, nonce, this.precomputed)
        != 0) {
      return null;
    }

    return output;
  }

  public static void genkeypair(byte[] publickey, byte[] privatekey) {
    genkeypair(publickey, privatekey, null);
  }

  public static void genkeypair(byte[] publickey, byte[] privatekey, byte[] seed) {
    SecureRandom random = new SecureRandom();

    random.nextBytes(privatekey);

    if (seed != null) {
      if (seed.length != SECRETKEYBYTES) {
        throw new Error("Invalid seed length");
      }

      for (int i = 0; i < SECRETKEYBYTES; i++) {
        privatekey[i] ^= seed[i];
      }
    }

    curve25519xsalsa20poly1305.crypto_box_getpublickey(publickey, privatekey);
  }

  public static byte[] derivePublicKey(byte[] privatekey) {
    if (privatekey.length != SECRETKEYBYTES) {
      throw new Error("Invalid private key length");
    }

    byte[] publickey = new byte[PUBLICKEYBYTES];
    curve25519xsalsa20poly1305.crypto_box_getpublickey(publickey, privatekey);
    return publickey;
  }

  public static byte[] symmetricEncryptData(byte[] input, byte[] key, byte[] nonce) {
    if (key.length != SYMMKEYBYTES) {
      throw new Error("Invalid symmetric key length");
    }

    if (nonce.length != NONCEBYTES) {
      throw new Error("Invalid nonce length");
    }

    byte[] output = new byte[input.length + BOXOVERHEAD];
    xsalsa20poly1305.crypto_secretbox_nopad(output, 0, input, 0, input.length, nonce, key);

    return output;
  }

  /**
   * In-place version of {@link #symmetricEncryptData(byte[], byte[], byte[])} that stores the
   * output in the same byte array as the input. The input data must begin at offset {@link
   * #BOXOVERHEAD} in the array (the first BOXOVERHEAD bytes are ignored and will be overwritten
   * with the message authentication code during encryption).
   *
   * @param io plaintext on input (starting at offset BOXOVERHEAD), ciphertext on return (full
   *     array)
   * @param key encryption key
   * @param nonce encryption nonce
   */
  public static void symmetricEncryptDataInplace(byte[] io, byte[] key, byte[] nonce) {

    if (key.length != SYMMKEYBYTES) {
      throw new Error("Invalid symmetric key length");
    }

    if (nonce.length != NONCEBYTES) {
      throw new Error("Invalid nonce length");
    }

    if (io.length < BOXOVERHEAD) {
      throw new Error("Invalid I/O length");
    }

    xsalsa20poly1305.crypto_secretbox_nopad(
        io, 0, io, BOXOVERHEAD, io.length - BOXOVERHEAD, nonce, key);
  }

  public static byte[] symmetricDecryptData(byte[] input, byte[] key, byte[] nonce) {
    if (key.length != SYMMKEYBYTES) {
      throw new Error("Invalid symmetric key length");
    }

    if (nonce.length != NONCEBYTES) {
      throw new Error("Invalid nonce length");
    }

    byte[] output = new byte[input.length - BOXOVERHEAD];
    if (xsalsa20poly1305.crypto_secretbox_open_nopad(output, 0, input, 0, input.length, nonce, key)
        != 0) {
      return null;
    }

    return output;
  }

  /**
   * In-place version of {@link #symmetricDecryptData(byte[], byte[], byte[])} that stores the
   * output in the same byte array as the input. Note that the decrypted output is shorter than the
   * input, so the last {@link #BOXOVERHEAD} bytes should be ignored in the decrypted output.
   *
   * @param io ciphertext on input (full array), plaintext on output (last BOXOVERHEAD bytes set to
   *     zero)
   * @param key encryption key
   * @param nonce encryption nonce
   * @return decryption successful true/false
   */
  public static boolean symmetricDecryptDataInplace(byte[] io, byte[] key, byte[] nonce) {
    if (key.length != SYMMKEYBYTES) {
      throw new Error("Invalid symmetric key length");
    }

    if (nonce.length != NONCEBYTES) {
      throw new Error("Invalid nonce length");
    }

    if (io.length < BOXOVERHEAD) {
      throw new Error("Invalid I/O length");
    }

    if (xsalsa20poly1305.crypto_secretbox_open_nopad(io, 0, io, 0, io.length, nonce, key) != 0) {
      return false;
    }

    /* zeroize last bytes */
    for (int i = io.length - BOXOVERHEAD; i < io.length; i++) {
      io[i] = 0;
    }

    return true;
  }

  public static byte[] streamCryptData(byte[] input, byte[] key, byte[] nonce) {
    if (key.length != STREAMKEYBYTES) {
      throw new Error("Invalid symmetric key length");
    }

    byte[] output = new byte[input.length];
    xsalsa20.crypto_stream_xor(output, input, input.length, nonce, key);

    return output;
  }

  public static byte[] getBinary(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];

    for (int i = 0; i < len; i += 2) {
      data[i / 2] =
          (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
    }

    return data;
  }

  public static String asHex(byte[] buf) {
    try (Formatter formatter = new Formatter()) {
      for (byte b : buf) {
        formatter.format("%02x", b);
      }
      return formatter.toString();
    }
  }

  public static String asHex(int[] buf) {
    try (Formatter formatter = new Formatter()) {
      for (int b : buf) {
        formatter.format("%02x", b);
      }
      return formatter.toString();
    }
  }
}
