/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.muni.fi.xklinec.whiteboxAES.generator;

import org.bouncycastle.pqc.math.linearalgebra.GF2mField;

import cz.muni.fi.xklinec.whiteboxAES.AES;
import cz.muni.fi.xklinec.whiteboxAES.State;
import junit.framework.TestCase;

/*
 * Copyright (c) 2014, Dusan (Ph4r05) Klinec, Petr Svenda
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
        System.out.println("keySchedule");
        AEShelper a = new AEShelper();
        a.build(true);
        
        // test sample key schedule
        byte[] roundKey = a.keySchedule(AEShelper.testVect128_key, 16, false);
        
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
    
    public void testKeyDependentMDS16x16() {
    	System.out.println("test Key-dependent MDS16x16");

        byte key[] = new byte[]{
                (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
                (byte)0xab, (byte)0xf7, (byte)0x17, (byte)0x88, //(byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88, 
                (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c };

        AEShelper a = new AEShelper();
        a.build(true);
    	
    	a.createMDS16x16(key);
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
    	
    	a.createMDS16x16(key);
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
}
