package com.neilalexander.jnacl;

import com.neilalexander.jnacl.crypto.curve25519;
import com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305;
import com.neilalexander.jnacl.crypto.xsalsa20;
import com.neilalexander.jnacl.crypto.xsalsa20poly1305;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES;
import static com.neilalexander.jnacl.crypto.curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES;
import static org.fest.assertions.Assertions.assertThat;

public class ScalarMultTest {

    @BeforeMethod
    public void setUp() throws Exception {
    }

    /**
     * Test public key computation (Alice)
     * See chapter 3 "Example of the sender’s keys" of Cryptography in NaCl, Daniel J. Bernstein
     * https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void test_crypto_scalarmult_curve25519_alice() throws Exception {
        byte[] alicesk = new byte[]{
                (byte) 0x77, (byte) 0x07, (byte) 0x6d, (byte) 0x0a, (byte) 0x73, (byte) 0x18, (byte) 0xa5, (byte) 0x7d,
                (byte) 0x3c, (byte) 0x16, (byte) 0xc1, (byte) 0x72, (byte) 0x51, (byte) 0xb2, (byte) 0x66, (byte) 0x45,
                (byte) 0xdf, (byte) 0x4c, (byte) 0x2f, (byte) 0x87, (byte) 0xeb, (byte) 0xc0, (byte) 0x99, (byte) 0x2a,
                (byte) 0xb1, (byte) 0x77, (byte) 0xfb, (byte) 0xa5, (byte) 0x1d, (byte) 0xb9, (byte) 0x2c, (byte) 0x2a
        };
        byte[] expected_alicepk = new byte[]{
                (byte) 0x85, (byte) 0x20, (byte) 0xf0, (byte) 0x09, (byte) 0x89, (byte) 0x30, (byte) 0xa7, (byte) 0x54,
                (byte) 0x74, (byte) 0x8b, (byte) 0x7d, (byte) 0xdc, (byte) 0xb4, (byte) 0x3e, (byte) 0xf7, (byte) 0x5a,
                (byte) 0x0d, (byte) 0xbf, (byte) 0x3a, (byte) 0x0d, (byte) 0x26, (byte) 0x38, (byte) 0x1a, (byte) 0xf4,
                (byte) 0xeb, (byte) 0xa4, (byte) 0xa9, (byte) 0x8e, (byte) 0xaa, (byte) 0x9b, (byte) 0x4e, (byte) 0x6a
        };
        byte[] alicepk = new byte[crypto_secretbox_PUBLICKEYBYTES];
        curve25519.crypto_scalarmult_base(alicepk, alicesk);
        assertThat(alicepk).isEqualTo(expected_alicepk);
    }

    /**
     * Test public key computation (Bob)
     * See chapter 4 "Example of the receiver’s keys" of Cryptography in NaCl, Daniel J. Bernstein
     * https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void test_crypto_scalarmult_curve25519_bob() throws Exception {
        byte[] bobsk = new byte[]{
                (byte) 0x5d, (byte) 0xab, (byte) 0x08, (byte) 0x7e, (byte) 0x62, (byte) 0x4a, (byte) 0x8a, (byte) 0x4b,
                (byte) 0x79, (byte) 0xe1, (byte) 0x7f, (byte) 0x8b, (byte) 0x83, (byte) 0x80, (byte) 0x0e, (byte) 0xe6,
                (byte) 0x6f, (byte) 0x3b, (byte) 0xb1, (byte) 0x29, (byte) 0x26, (byte) 0x18, (byte) 0xb6, (byte) 0xfd,
                (byte) 0x1c, (byte) 0x2f, (byte) 0x8b, (byte) 0x27, (byte) 0xff, (byte) 0x88, (byte) 0xe0, (byte) 0xeb
        };
        byte[] expected_bobpk = new byte[]{
                (byte) 0xde, (byte) 0x9e, (byte) 0xdb, (byte) 0x7d, (byte) 0x7b, (byte) 0x7d, (byte) 0xc1, (byte) 0xb4,
                (byte) 0xd3, (byte) 0x5b, (byte) 0x61, (byte) 0xc2, (byte) 0xec, (byte) 0xe4, (byte) 0x35, (byte) 0x37,
                (byte) 0x3f, (byte) 0x83, (byte) 0x43, (byte) 0xc8, (byte) 0x5b, (byte) 0x78, (byte) 0x67, (byte) 0x4d,
                (byte) 0xad, (byte) 0xfc, (byte) 0x7e, (byte) 0x14, (byte) 0x6f, (byte) 0x88, (byte) 0x2b, (byte) 0x4f
        };
        byte[] bobpk = new byte[crypto_secretbox_PUBLICKEYBYTES];
        curve25519.crypto_scalarmult_base(bobpk, bobsk);
        assertThat(bobpk).isEqualTo(expected_bobpk);
    }

    /**
     * Test shared secret agreement
     * See chapter 6 "Example of the shared secret" of Cryptography in NaCl, Daniel J. Bernstein
     * https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
     */
    @Test
    public void test_crypto_scalarmult_curve25519() throws Exception {
        byte[] alicesk = new byte[]{
                (byte) 0x77, (byte) 0x07, (byte) 0x6d, (byte) 0x0a, (byte) 0x73, (byte) 0x18, (byte) 0xa5, (byte) 0x7d,
                (byte) 0x3c, (byte) 0x16, (byte) 0xc1, (byte) 0x72, (byte) 0x51, (byte) 0xb2, (byte) 0x66, (byte) 0x45,
                (byte) 0xdf, (byte) 0x4c, (byte) 0x2f, (byte) 0x87, (byte) 0xeb, (byte) 0xc0, (byte) 0x99, (byte) 0x2a,
                (byte) 0xb1, (byte) 0x77, (byte) 0xfb, (byte) 0xa5, (byte) 0x1d, (byte) 0xb9, (byte) 0x2c, (byte) 0x2a
        };
        byte[] alicepk = new byte[crypto_secretbox_PUBLICKEYBYTES];
        curve25519.crypto_scalarmult_base(alicepk, alicesk);
        byte[] bobsk = new byte[]{
                (byte) 0x5d, (byte) 0xab, (byte) 0x08, (byte) 0x7e, (byte) 0x62, (byte) 0x4a, (byte) 0x8a, (byte) 0x4b,
                (byte) 0x79, (byte) 0xe1, (byte) 0x7f, (byte) 0x8b, (byte) 0x83, (byte) 0x80, (byte) 0x0e, (byte) 0xe6,
                (byte) 0x6f, (byte) 0x3b, (byte) 0xb1, (byte) 0x29, (byte) 0x26, (byte) 0x18, (byte) 0xb6, (byte) 0xfd,
                (byte) 0x1c, (byte) 0x2f, (byte) 0x8b, (byte) 0x27, (byte) 0xff, (byte) 0x88, (byte) 0xe0, (byte) 0xeb
        };
        byte[] bobpk = new byte[crypto_secretbox_PUBLICKEYBYTES];
        curve25519.crypto_scalarmult_base(bobpk, bobsk);
        byte[] expected_shared = new byte[]{
                (byte) 0x4a, (byte) 0x5d, (byte) 0x9d, (byte) 0x5b, (byte) 0xa4, (byte) 0xce, (byte) 0x2d, (byte) 0xe1,
                (byte) 0x72, (byte) 0x8e, (byte) 0x3b, (byte) 0xf4, (byte) 0x80, (byte) 0x35, (byte) 0x0f, (byte) 0x25,
                (byte) 0xe0, (byte) 0x7e, (byte) 0x21, (byte) 0xc9, (byte) 0x47, (byte) 0xd1, (byte) 0x9e, (byte) 0x33,
                (byte) 0x76, (byte) 0xf0, (byte) 0x9b, (byte) 0x3c, (byte) 0x1e, (byte) 0x16, (byte) 0x17, (byte) 0x42
        };
        byte[] alice_shared = new byte[32];
        curve25519.crypto_scalarmult(alice_shared, alicesk, bobpk);
        byte[] bob_shared = new byte[32];
        curve25519.crypto_scalarmult(bob_shared, bobsk, alicepk);
        assertThat(alice_shared).isEqualTo(expected_shared);
        assertThat(bob_shared).isEqualTo(expected_shared);
    }

    /**
     * Test multiple randomly generated shared secret agreements
     */
    @Test
    public void test_crypto_scalarmult_curve25519_random() throws Exception {
        for (int i = 0; i < 50; i++) {
            byte[] alicepk = new byte[crypto_secretbox_PUBLICKEYBYTES];
            byte[] alicesk = new byte[crypto_secretbox_SECRETKEYBYTES];
            byte[] bobpk = new byte[crypto_secretbox_PUBLICKEYBYTES];
            byte[] bobsk = new byte[crypto_secretbox_SECRETKEYBYTES];
            curve25519xsalsa20poly1305.crypto_box_keypair(alicepk, alicesk);
            curve25519xsalsa20poly1305.crypto_box_keypair(bobpk, bobsk);
            byte[] alice_shared = new byte[32];
            byte[] bob_shared = new byte[32];
            curve25519.crypto_scalarmult(alice_shared, alicesk, bobpk);
            curve25519.crypto_scalarmult(bob_shared, bobsk, alicepk);
            assertThat(alice_shared).isEqualTo(bob_shared);
        }
    }

}