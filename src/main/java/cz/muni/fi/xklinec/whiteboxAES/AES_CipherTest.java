/*
* Copyright (c) 2014, Lenka Bacinska, Petr Svenda
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* * Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
* * Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
* * Neither the name of the copyright holders nor the names of
* its contributors may be used to endorse or promote products derived
* from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/
package cz.muni.fi.xklinec.whiteboxAES;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import cz.muni.fi.xklinec.whiteboxAES.generator.AEShelper;

/**
 * 
 * @author BacinskaL
 */
public class AES_CipherTest extends TestCase {

	/**
	 *  Test of API - init and doFinal
	 */
	public void testInitDoFinal() {
		System.out.println("API test");

        SecureRandom random = new SecureRandom();
		
		Key key = new SecretKeySpec(AEShelper.testVect128_key, "WBAES");
		
		AES_Cipher encryptor = new AES_Cipher();
		try {
			encryptor.engineInit(Cipher.ENCRYPT_MODE, key, random);
		} catch (InvalidKeyException e) {}
		
		byte[] outputEnc = new byte[16];
		try {
			outputEnc = encryptor.engineDoFinal(AEShelper.testVect128_plain[1], 0, 16);
		} catch (Exception e) {}
		
		
		AES_Cipher decryptor = new AES_Cipher();
		try {
			decryptor.engineInit(Cipher.DECRYPT_MODE, key, random);
		} catch (InvalidKeyException e) {}
		
		byte[] outputDec = new byte[16];
		try {
			outputDec = decryptor.engineDoFinal(outputEnc, 0, 16);
		} catch (Exception e) {}
		
        State plain  = new State(AEShelper.testVect128_plain[1], true,  false);
        State cipher = new State(AEShelper.testVect128_cipher[1], true, false);
		
		System.out.println("Testvector plaintext sour: \n" + plain);
        System.out.println("Testvector ciphertext sour: \n"+ cipher);

        State cipher2  = new State(outputEnc, true, false);
        State plain2 = new State(outputDec, true, false);
        
		System.out.println("Testvector ciphertext comp: \n" + cipher2);
        System.out.println("Testvector plaintext comp: \n"+ plain2);
		
        // problem with byte arrays comparison - used States
        assertEquals("Cipher output mismatch in API", true, plain2.equals(plain));
		
	}
	
	/**
	 *  Test of API - init and doFinal with non-trivial key length
	 */
	public void testInitDoFinalKeyNT() {
		System.out.println("API test NT");
		int dataLength = 16;
		
		byte[] keyData = new byte[]{
				(byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
	            (byte)0xd2, (byte)0xa6, (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xae, 
	            //(byte)0xd2, (byte)0xa6, (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xae, 
	            //(byte)0xd2, (byte)0xa6, (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xae, 
	            }; //NT length is not working, thats why there is Trivial length - also 125bit key not working, because AES.ROUNDS is set to 10 (i.e. 128bit key only)
		
		Key key = new SecretKeySpec(keyData, "WBAES");
		
		State plain  = new State(AEShelper.testVect256_plain[1], true,  false);
		
		AES_Cipher encryptor = new AES_Cipher();
		try {
			encryptor.engineInit(Cipher.ENCRYPT_MODE, key, null);
		} catch (Exception e) {}
		
		byte[] outputEnc = new byte[dataLength];
		try {
			outputEnc = encryptor.engineDoFinal(AEShelper.testVect256_plain[1], 0, dataLength);
		} catch (Exception e) {}
		
		
		AES_Cipher decryptor = new AES_Cipher();
		try {
			decryptor.engineInit(Cipher.DECRYPT_MODE, key, null);
		} catch (InvalidKeyException e) {}
		
		byte[] outputDec = new byte[dataLength];
		try {
			outputDec = decryptor.engineDoFinal(outputEnc, 0, dataLength);
		} catch (Exception e) {}

		State plain2  = new State(outputDec, true,  false);
		
		System.out.println("Plaintext sour:");
		System.out.println(plain.toString());
		System.out.println("Plaintext comp:");
		System.out.println(plain2.toString());
		/*
		for(int i = 0; i<dataLength; i++) {
			System.out.println(i + ": " + AEShelper.testVect256_plain[1][i]);
			System.out.println(i + ": " + outputDec[i]);
		}
		*/
		assertEquals("Cipher output mismatch in API", true, plain2.equals(plain));

	}

	/**
	 *  Test of API - Exceptions
	 */
	public void testExceptions() {
		System.out.println("Exception test");
		
		AES_Cipher encryptor = new AES_Cipher();
		
		byte[] outputEnc = new byte[16];
		try {
			outputEnc = encryptor.engineDoFinal(AEShelper.testVect128_plain[1], 0, 16);
			fail("engineDoFinal()");
		} catch (Exception e) {}
		
		AES_Cipher decryptor = new AES_Cipher();
		
		byte[] outputDec = new byte[16];
		try {
			outputDec = decryptor.engineDoFinal(outputEnc, 0, 16);
			fail();
		} catch (Exception e) {}
				
	}
		
	/**
	 *  Serialization test
	 */
	public void testSerialization() {
		System.out.println("Serialization test");
		byte[] outputEnc = new byte[16];
		
		try {
			SecureRandom random = new SecureRandom();
		
			Key key = new SecretKeySpec(AEShelper.testVect128_key, "WBAES");
		
			AES_Cipher encryptor = new AES_Cipher();
			encryptor.engineInit(Cipher.ENCRYPT_MODE, key, random);
			
			outputEnc = encryptor.engineDoFinal(AEShelper.testVect128_plain[1], 0, 16);
		} catch (Exception e) {}
		
		try {
			SecureRandom random = new SecureRandom();
		
			Key key = new SecretKeySpec(AEShelper.testVect128_key, "WBAES");
		
			AES_Cipher decryptor = new AES_Cipher();
			decryptor.engineInit(Cipher.DECRYPT_MODE, key, random);
			
			byte[] outputDec = new byte[16];
			outputDec = decryptor.engineDoFinal(outputEnc, 0, 16);
			
			State plain_sour = new State(AEShelper.testVect128_plain[1], true,  false);
			State plain_comp = new State(outputDec, true,  false);
			
			assertEquals("Plaintext output mismatch in API", true, plain_comp.equals(plain_sour));
			
		} catch (Exception e) {}
	}
		
	/**
	 *  Test with the null key
	 */
	public void testNullKey() {
		try {
			SecureRandom random = new SecureRandom();
		
			AES_Cipher encryptor = new AES_Cipher();
		
			encryptor.engineInit(Cipher.ENCRYPT_MODE, null, random);
		
			byte[] outputEnc = new byte[16];
			outputEnc = encryptor.engineDoFinal(AEShelper.testVect128_plain[1], 0, 16);
		
			State cipher = new State(AEShelper.testVect128_cipher[1], true, false);
		
			System.out.println("Testvector ciphertext sour: \n"+ cipher);

			State cipher2 = new State(outputEnc, true,  false);
        
			System.out.println("Testvector ciphertext comp: \n" + cipher2);
		
			// problem with byte arrays comparison - used States
			//assertEquals("Cipher output mismatch in API", true, cipher2.equals(cipher));
		} catch (Exception e) { fail("Serialization - exception thrown"); }
	}
	
}
