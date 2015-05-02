/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.xklinec.whiteboxAES.generator;

import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;

import cz.muni.fi.xklinec.whiteboxAES.AES;
import cz.muni.fi.xklinec.whiteboxAES.State;
import junit.framework.TestCase;

/*
 * Copyright (c) 2014, Dusan (Ph4r05) Klinec, Lenka Bacinska, Petr Svenda
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the copyright holders nor the names of
 *   its contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
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
public class AEShelperTest extends TestCase {
    
    public AEShelperTest(String testName) {
        super(testName);
    }
    
    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }
    
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of build method, of class AEShelper.
     */
    public void testBuild() {
        System.out.println("build");
        AEShelper a = new AEShelper();
        a.build(true);
        
        // test AES S-box - some fixed tests
        assertEquals("S-box value mismatch", 0x63, a.ByteSub(0));
        assertEquals("S-box value mismatch", 0x76, a.ByteSub(0x0f));
        assertEquals("S-box value mismatch", 0x16, a.ByteSub(0xff));
        assertEquals("S-box value mismatch", 0x0e, a.ByteSub(0xd7));
        assertEquals("S-box value mismatch", 0x3c, a.ByteSub(0x6d));
        
        // S-Box inversion test.
        for(int i=0; i<256; i++){
            int b = a.ByteSub(i);
            b = a.ByteSubInv(b);
            assertEquals("S-box inversion value mismatch", i, b);
        }
        
        // RCON test
        for(int i=0; i<8; i++){
            assertEquals("RCON is invalid", 1<<i, a.RC[i]);
        }
        
        assertEquals("RCON is invalid", 0x1B, a.RC[8]);
        assertEquals("RCON is invalid", 0x36, a.RC[9]);
    }

    /**
     * Test of build method, of class AEShelper.
     */
    public void testKeySchedule() {
        System.out.println("keySchedule - old, with hashChain not working");
        AEShelper a = new AEShelper();
        a.build(true);
        
        // test sample key schedule
        byte[] roundKey = a.keySchedule(AEShelper.testVect128_key[0], 16, false);
        
        // test copy of key
        for(int i=0; i<16; i++){
            assertEquals("Key schedule is invalid", AEShelper.testVect128_key[i],  roundKey[i]);
        }
        
        // test key schedule for the last round. Alg. is iterative and current 
        // round depends on the last one -> it is enough to test the last one.
        // Source: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
        final byte[] roundKeyFinal = new byte[] {
            (byte)0xd0, (byte)0x14, (byte)0xf9, (byte)0xa8,
            (byte)0xc9, (byte)0xee, (byte)0x25, (byte)0x89,
            (byte)0xe1, (byte)0x3f, (byte)0x0c, (byte)0xc8,
            (byte)0xb6, (byte)0x63, (byte)0x0c, (byte)0xa6
        };
        
        for(int i=0; i<16; i++){
            assertEquals("Key schedule is invalid; last round check", 
                roundKeyFinal[i],
                roundKey[AES.BYTES * AES.ROUNDS + i]);
        }
    }
    
    /**
     * Test of hashChain generation
     */
    public void testHashChain() {
    	System.out.println("test hashChain");
    	
        byte key[] = new byte[]{
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c };
    	
        
        AEShelper a = new AEShelper();
        a.build(true);
        
        // test sample hash chain
        byte[] roundKey = a.hashChain(key, 16, "Salt", false);
        
        for(int i=0; i<16; i++){
            System.out.println(Integer.toHexString((int)roundKey[AES.BYTES * AES.ROUNDS + i]));
        }
        //fail();
    }
    
    /**
     * Test of constant MDS16x16 matrix generation
     */
    public void testIndependentMDS16x16() {
    	System.out.println("test Independent (constant) MDS16x16");

        AEShelper a = new AEShelper();
        a.build(true);
    	
    	a.createMDS16x16();
    	int matrixInt[][] = a.getMDS16x16();
    	byte matrixByte[][] = new byte[16][16];
    	
    	for(int i = 0; i<16; i++)
    		for(int j = 0; j<16; j++)
    			matrixByte[i][j] = (byte)matrixInt[i][j];
    	
    	for(int i = 0; i<16; i++) {
    		State matrixRow  = new State(matrixByte[i], true,  false);
    		System.out.println(i + ": " + matrixRow.toString());
    	}
    }
    
    /**
     * Test of key-dependent MDS16x16 matrix generation
     */
    public void testKeyDependentMDS16x16() {
    	System.out.println("test Key-dependent MDS16x16");

        byte key[] = new byte[]{
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x17, (byte)0x88, //(byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88, 
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c };

        AEShelper a = new AEShelper();
        a.build(true);
    	
    	a.createMDS16x16(key, true);
    	int matrixInt[][] = a.getMDS16x16();
    	byte matrixByte[][] = new byte[16][16];
    	
    	for(int i = 0; i<16; i++)
    		for(int j = 0; j<16; j++)
    			matrixByte[i][j] = (byte)matrixInt[i][j];
    	
    	for(int i = 0; i<16; i++) {
    		State matrixRow  = new State(matrixByte[i], true,  false);
    		System.out.println(i + ": " + matrixRow.toString());
    	}
    }

    /**
     * Test of constant MDS16x16 matrix generation with multiplication by itself - should be neutral
     */
    public void testIndependentMDS16x16Inverse() {
    	System.out.println("test Independent (constant) MDS16x16 - multiplicated by inverse");

    	int i,c;
    	GF2mField field = new GF2mField(8, 0x11B);
    	
        AEShelper a = new AEShelper();
        a.build(true);
    	
    	a.createMDS16x16();

    	int MDS16x16[][] = a.getMDS16x16();
    	GF2mMatrixEx MDS16x16Mat = new GF2mMatrixEx(field, 16, 16);
		for(i=0; i<16; i++){
            for(c=0; c<16; c++){
            	MDS16x16Mat.set(i, c, MDS16x16[i][c]);
            }
		}
		
		GF2mMatrixEx shouldBeI = MDS16x16Mat.rightMultiply(MDS16x16Mat);
		System.out.println(shouldBeI.toString());
    }
    
    /**
     * Test of key-dependent MDS16x16 matrix generation with multiplication by itself - should be neutral
     */
    public void testKeyDependentMDS16x16Inverse() {
    	System.out.println("test Key-dependent MDS16x16 - multiplicated by inverse");
    	
    	int i,c;
    	GF2mField field = new GF2mField(8, 0x11B);
    	
        byte key[] = new byte[]{
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x17, (byte)0x88, //(byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88, 
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c };

        AEShelper a = new AEShelper();
        a.build(true);
    	
    	a.createMDS16x16(key, true);
    	int MDS16x16[][] = a.getMDS16x16();
    	GF2mMatrixEx MDS16x16Mat = new GF2mMatrixEx(field, 16, 16);
		for(i=0; i<16; i++){
            for(c=0; c<16; c++){
            	MDS16x16Mat.set(i, c, MDS16x16[i][c]);
            }
		}
		
		GF2mMatrixEx shouldBeI = MDS16x16Mat.rightMultiply(MDS16x16Mat);
		System.out.println(shouldBeI.toString());
    }
    
    /**
     * Test of various (not suitable) keys for MDS16x16 generation
     */
    public void testSuitableKeysForMDS16x16() {
    	
    	byte key[] = new byte[]{
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x17, (byte)0x88, //(byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88, 
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c };
    	
    	AEShelper a = new AEShelper();
        a.build(true);
    	
    	if(a.createMDS16x16(key, true) == null) fail();
    	
    	a.generateKeyDependentMDSmatrices(key, key.length, true, true);

    }
    
    /**
     * Partial computation of test vectors
     */
    public void testVectorsGeneration() {

    	System.out.println("test vectors generation");    	
    	
    	// plaintext from AES test vectors
    	byte plaintext[] = AEShelper.testVect128_plain[0];
        State plaintext_string  = new State(plaintext, true,  false);
        System.out.println("- plaintext_string: " + plaintext_string);

    	// key from AES test vectors
        byte key[] = AEShelper.testVect128_key[0];
        State key_string  = new State(key, true,  false);
        System.out.println("- key_string: " + key_string);

        // just a helper
        AEShelper a = new AEShelper();
        a.build(true);

        // hash chain - round keys generation
        byte[] roundKeys = a.hashChain(key, 16, AES.SALT, false);

        for(int r=0; r<AES.ROUNDS + 1; r++){
        	byte roundKey[] = new byte[AES.BYTES];
        	System.arraycopy(roundKeys, AES.BYTES * r, roundKey, 0, AES.BYTES);
            State roundKey_string  = new State(roundKey, true,  false);
            System.out.println("- key_string " + r + ": " + roundKey_string);
        }

        // hash chain - round keys for S-boxes
    	byte[] key_sboxes = new byte[key.length + AES.SBOXconstant.length];
    	System.arraycopy(key, 0, key_sboxes, 0, key.length);
    	System.arraycopy(AES.SBOXconstant, 0, key_sboxes, key.length, AES.SBOXconstant.length);
        byte[] roundKeysForSboxes = a.hashChain(key_sboxes, key.length, AES.SALT, false);

        for(int r=0; r<AES.ROUNDS + 1; r++){
        	byte roundKey[] = new byte[AES.BYTES];
        	System.arraycopy(roundKeysForSboxes, AES.BYTES * r, roundKey, 0, AES.BYTES);
            State roundKey_string  = new State(roundKey, true,  false);
            System.out.println("- S-box_key_string " + r + ": " + roundKey_string);
        }

        // hash chain - round keys for MDS matrices
    	byte[] key_MDS = new byte[key.length + AES.MDSconstant.length];
    	System.arraycopy(key, 0, key_MDS, 0, key.length);
    	System.arraycopy(AES.MDSconstant, 0, key_MDS, key.length, AES.MDSconstant.length);
        byte[] roundKeysForMDS = a.hashChain(key_MDS, key.length, AES.SALT, false);

        for(int r=0; r<AES.ROUNDS + 1; r++){
        	byte roundKey[] = new byte[AES.BYTES];
        	System.arraycopy(roundKeysForMDS, AES.BYTES * r, roundKey, 0, AES.BYTES);
            State roundKey_string  = new State(roundKey, true,  false);
            System.out.println("- MDS_key_string " + r + ": " + roundKey_string);
        }

        // all rounds of the cipher
    	for(int r = 0; r<AES.ROUNDS; r++) {
    		System.out.println("r = " + r);
    		
    		byte[] roundKeyForSboxes = new byte[key.length];
    		System.arraycopy(roundKeysForSboxes, key.length*r, roundKeyForSboxes, 0, key.length);
        	byte key_bytesForSboxes[] = new byte[64];
        	
    		try {
        		MessageDigest md = MessageDigest.getInstance("SHA-512");
        		md.update(roundKeyForSboxes);
        		key_bytesForSboxes = md.digest();
    		} catch(Exception e) { //NoSuchAlgorithmException
    			System.out.println("Problem with SHA512 in keyBytesDerivation (used in createKeyDependentSboxes).");
    		}
    		
            // addRoundKey
            for(int i = 0; i<AES.BYTES; i++)
            	plaintext[i] ^= roundKeys[AES.BYTES * r + i];
            State plaintext_ARK_string  = new State(plaintext, true,  false);
            System.out.println("- plaintext_ARK_string: " + plaintext_ARK_string);
            
    		// subBytes
	    	byte state_bytes[] = new byte[AES.BYTES];
		    state_bytes[0] = (byte) a.sboxgen(0,13,(int)plaintext[0] & 0xff,key_bytesForSboxes);
		    state_bytes[1] = (byte) a.sboxgen(1,13,(int)plaintext[1] & 0xff,key_bytesForSboxes);
		    state_bytes[2] = (byte) a.sboxgen(2,13,(int)plaintext[2] & 0xff,key_bytesForSboxes);
		    state_bytes[3] = (byte) a.sboxgen(3,13,(int)plaintext[3] & 0xff,key_bytesForSboxes);

		    state_bytes[4] = (byte) a.sboxgen(0,13,(int)plaintext[4] & 0xff,key_bytesForSboxes);
		    state_bytes[5] = (byte) a.sboxgen(1,13,(int)plaintext[5] & 0xff,key_bytesForSboxes);
		    state_bytes[6] = (byte) a.sboxgen(2,13,(int)plaintext[6] & 0xff,key_bytesForSboxes);
		    state_bytes[7] = (byte) a.sboxgen(3,13,(int)plaintext[7] & 0xff,key_bytesForSboxes);

		    state_bytes[8]  = (byte) a.sboxgen(0,13,(int)plaintext[8] & 0xff,key_bytesForSboxes);
		    state_bytes[9]  = (byte) a.sboxgen(1,13,(int)plaintext[9] & 0xff,key_bytesForSboxes);
		    state_bytes[10] = (byte) a.sboxgen(2,13,(int)plaintext[10] & 0xff,key_bytesForSboxes);
		    state_bytes[11] = (byte) a.sboxgen(3,13,(int)plaintext[11] & 0xff,key_bytesForSboxes);

		    state_bytes[12] = (byte) a.sboxgen(0,13,(int)plaintext[12] & 0xff,key_bytesForSboxes);
		    state_bytes[13] = (byte) a.sboxgen(1,13,(int)plaintext[13] & 0xff,key_bytesForSboxes);
		    state_bytes[14] = (byte) a.sboxgen(2,13,(int)plaintext[14] & 0xff,key_bytesForSboxes);
		    state_bytes[15] = (byte) a.sboxgen(3,13,(int)plaintext[15] & 0xff,key_bytesForSboxes);

    		System.arraycopy(state_bytes, 0, plaintext, 0, AES.BYTES);
            State plaintext_SB_string  = new State(plaintext, true,  false);
            System.out.println("- plaintext_SB_string: " + plaintext_SB_string);
            
    		// shiftRows
		    state_bytes[0] = plaintext[0];
		    state_bytes[1] = plaintext[5];
		    state_bytes[2] = plaintext[10];
		    state_bytes[3] = plaintext[15];
		    
		    state_bytes[4] = plaintext[4];
		    state_bytes[5] = plaintext[9];
		    state_bytes[6] = plaintext[14];
		    state_bytes[7] = plaintext[3];
		    
		    state_bytes[8]  = plaintext[8];
		    state_bytes[9]  = plaintext[13];
		    state_bytes[10] = plaintext[2];
		    state_bytes[11] = plaintext[7];
		    
		    state_bytes[12] = plaintext[12];
		    state_bytes[13] = plaintext[1];
		    state_bytes[14] = plaintext[6];
		    state_bytes[15] = plaintext[11];
    		System.arraycopy(state_bytes, 0, plaintext, 0, AES.BYTES);
            State plaintext_SR_string  = new State(plaintext, true,  false);
            System.out.println("- plaintext_SR_string: " + plaintext_SR_string);

            // MDS matrix multiplication - not in the final round
            if(r != AES.ROUNDS - 1) {
            	// matica len dvojrozmerne pole, ziadny specialny objekt, nasobenie rucne

        		byte[] roundKeyForMDS = new byte[key.length];
        		System.arraycopy(roundKeysForMDS, key.length*r, roundKeyForMDS, 0, key.length);
                //State roundKeyForMDS_string  = new State(roundKeyForMDS, true,  false);
                //System.out.println("- roundKeyForMDS_string: " + roundKeyForMDS_string);
            	
                // MDS matrix generation
        		int[][] MDS16x16int = a.createMDS16x16(roundKeyForMDS, true);
        		//byte[][] MDS16x16byte = new byte[16][16];
        		//for(int i = 0; i<16; i++)
        		//	for(int j = 0; j<16; j++)
        		//		MDS16x16byte[i][j] = (byte) MDS16x16int[i][j];
                //State firstRowMDS_string  = new State(MDS16x16byte[0], true,  false);
                //System.out.println("- firstRowMDS_string: " + firstRowMDS_string);

        		if(MDS16x16int == null) {
        			System.out.println("Generated matrix is null, a constant one should be used!");
        			MDS16x16int = a.getMDS16x16();
        		}

        		// transpose
    		    state_bytes[0] = plaintext[0];
    		    state_bytes[1] = plaintext[4];
    		    state_bytes[2] = plaintext[8];
    		    state_bytes[3] = plaintext[12];
    		    
    		    state_bytes[4] = plaintext[1];
    		    state_bytes[5] = plaintext[5];
    		    state_bytes[6] = plaintext[9];
    		    state_bytes[7] = plaintext[13];
    		    
    		    state_bytes[8]  = plaintext[2];
    		    state_bytes[9]  = plaintext[6];
    		    state_bytes[10] = plaintext[10];
    		    state_bytes[11] = plaintext[14];
    		    
    		    state_bytes[12] = plaintext[3];
    		    state_bytes[13] = plaintext[7];
    		    state_bytes[14] = plaintext[11];
    		    state_bytes[15] = plaintext[15];
        		System.arraycopy(state_bytes, 0, plaintext, 0, AES.BYTES);
                State plaintext_TR_string  = new State(plaintext, true,  false);
                System.out.println("- plaintext_TR_string: " + plaintext_TR_string);

                // MDS matrix multiplication
        		for(int i = 0; i<16; i++) {
                	state_bytes[i] = 0;
                	for(int j = 0; j<16; j++) {
                		int x = (int)plaintext[j] & 0xff;
                		for(int b = 0; b<8; b++) {
                			if(((MDS16x16int[i][j] >>> b) & 0x01) == 1) {
                				state_bytes[i] ^= (byte) x;
                			}
                			x = ((x << 1) & 0x100) == 0 ? x << 1 : (x << 1) ^ 283;
                		}
                	}
                }
                System.arraycopy(state_bytes, 0, plaintext, 0, AES.BYTES);
                State plaintext_MDS_string  = new State(plaintext, true,  false);
                System.out.println("- plaintext_MDS_string: " + plaintext_MDS_string);


        		// transpose back
    		    state_bytes[0] = plaintext[0];
    		    state_bytes[1] = plaintext[4];
    		    state_bytes[2] = plaintext[8];
    		    state_bytes[3] = plaintext[12];

    		    state_bytes[4] = plaintext[1];
    		    state_bytes[5] = plaintext[5];
    		    state_bytes[6] = plaintext[9];
    		    state_bytes[7] = plaintext[13];

    		    state_bytes[8]  = plaintext[2];
    		    state_bytes[9]  = plaintext[6];
    		    state_bytes[10] = plaintext[10];
    		    state_bytes[11] = plaintext[14];

    		    state_bytes[12] = plaintext[3];
    		    state_bytes[13] = plaintext[7];
    		    state_bytes[14] = plaintext[11];
    		    state_bytes[15] = plaintext[15];
        		System.arraycopy(state_bytes, 0, plaintext, 0, AES.BYTES);
                State plaintext_TR2_string  = new State(plaintext, true,  false);
                System.out.println("- plaintext_TR2_string: " + plaintext_TR2_string);
            }
            
    	}

        // addRoundKey
        for(int i = 0; i<AES.BYTES; i++)
        	plaintext[i] ^= roundKeys[AES.BYTES * 10 + i];
        State plaintext_end_string  = new State(plaintext, true,  false);
        System.out.println("- ciphertext_string: " + plaintext_end_string);

    }
    
}
