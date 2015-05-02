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
package cz.muni.fi.xklinec.whiteboxAES;

import java.util.Arrays;
import java.io.Serializable;

/**
 * Main AES whitebox table implementation.
 * 
 * @author ph4r05
 */
public class AES implements Serializable {

	private static final long serialVersionUID = 1L; // added serialization

	public static final int scrypt_N = 16384; //2^14 = 5sec, NOTE maybe change to 2^16 = 20sec
	public static final int scrypt_r = 8;
	public static final int scrypt_p = 1;

	public static final String SALT = "TheConstantSalt.";
	public static final byte[] SBOXconstant = new byte[] {'S','B','O','X','c','o','n','s','t','a','n','t'};
	public static final byte[] MDSconstant = new byte[] {'M','D','S', 'c','o','n','s','t','a','n','t'};
	
	public static final int BYTES  = State.BYTES;
    public static final int ROUNDS = 10;
    public static final int T1BOXES = 2;
    public static final int T1Boxes = 2;
    public static final int shiftRows[] = {
        0,   1,  2,  3,
        5,   6,  7,  4,
        10, 11,  8,  9,
        15, 12, 13, 14
    };
    
    public static final int shiftRowsInv[] = {
        0,  1,  2,  3,
        7,  4,  5,  6,
       10, 11,  8,  9,
       13, 14, 15, 12
    };
        
    protected T1Box[][]         t1       = new T1Box[T1BOXES][State.BYTES];
    protected XORCascadeState[] xorState = new XORCascadeState[T1BOXES];
    protected XORCascadeState[] xorState2 = new XORCascadeState[ROUNDS];
    protected XORCascadeState[] xorState3 = new XORCascadeState[ROUNDS];
    protected T2Box[][]         t2       = new T2Box[ROUNDS][State.BYTES];
    protected T3Box[][]         t3       = new T3Box[ROUNDS][State.BYTES];
    //protected XORCascade[][]    xor      = new XORCascade[ROUNDS][State.BYTES];
    private boolean           encrypt  = true;

    public static int posIdx(byte x){
        return x & 0xff;
    }
    
    public static int posIdx(int x){
        return x & 0xff;
    }
    
    /**
     * Encryption OR decryption - depends on generated tables
     * @param in 
     */
    public State crypt(State state){
        int r=0, i=0;
	State ires3[] = new State[BYTES];	// intermediate result for T2,T3-boxes
	State ires2[] = new State[BYTES];	// intermediate result for T2,T3-boxes
	State ares[] = new State[BYTES];	// intermediate result for T1-boxes
        
        // initialize ires, ares at first
        for(i=0; i<BYTES; i++){
            ires3[i] = new State();
            ires2[i] = new State();
            ares[i] = new State();
        }
        /*
        System.out.println("line 103");
        System.out.println(state);
        */
        // At first we have to put input to T1 boxes directly, no shift rows
	// compute result to ares[16]
	for(i=0; i<BYTES; i++){
            // Note: Tbox is indexed by cols, state by rows - transpose needed here
            ares[i].loadFrom( t1[0][i].lookup(state.get(i)) );
        }
        
        // now compute XOR cascade from 16 x 128bit result after T1 application.
        xorState[0].xor(ares);
        state.loadFrom(ares[0]);
        /*
        System.out.println("line 117");
        System.out.println(state);
        */
        // Compute 9 rounds of T2 boxes
        for(r=0; r<ROUNDS-1; r++){
            // Apply type 2 tables to all bytes, counting also shift rows selector.
            for(i=0; i<BYTES; i++){
                ires2[i].loadFrom(t2[r][i].lookup(state.get(shift(i))));
            }
            
            xorState2[r].xor(ires2);
            state.loadFrom(ires2[0]);
            /*
            System.out.println("line 132");
            System.out.println(state);
            */
            for(i=0; i<BYTES; i++){
            	ires3[i].loadFrom(t3[r][i].lookup(state.get(i)));
            }
            
            xorState3[r].xor(ires3);
            state.loadFrom(ires3[0]);

        }
        
        //
	// Final round is special -> T1 boxes
	//
        for(i=0; i<BYTES; i++){
            // Note: Tbox is indexed by cols, state by rows - transpose needed here
            ares[i].loadFrom( t1[1][i].lookup(state.get(shift(i))) );
        }
        
        // now compute XOR cascade from 16 x 128bit result after T1 application.
        xorState[1].xor(ares);
        state.loadFrom(ares[0]);
        /*
        System.out.println("line 154");
        System.out.println(state);
        */
        return state;
    }
    
    /**
     * Returns needed shift operation according to cipher direction (enc vs. dec).
     * 
     * @param encrypt
     * @return 
     */
    public static int[] getShift(boolean encrypt){
        return encrypt ? shiftRows : shiftRowsInv;
    }
    
    /**
     * Returns shifted bit 
     * 
     * @param idx
     * @param encrypt
     * @return 
     */
    public static int shift(int idx, boolean encrypt){
        return getShift(encrypt)[idx];
    }
    
    /**
     * Returns shifted bit 
     * 
     * @param idx
     * @param encrypt
     * @return 
     */
    public int shift(int idx){
        return getShift(encrypt)[idx];
    }
    
    
    /**
     * Memory allocation of each box
     */
    public void init(){
        int i,r;
        
        t1        = new T1Box[T1BOXES][BYTES];
        xorState  = new XORCascadeState[T1BOXES];
        xorState2  = new XORCascadeState[ROUNDS];
        xorState3  = new XORCascadeState[ROUNDS];
        t2        = new T2Box[ROUNDS][BYTES];
        t3        = new T3Box[ROUNDS][BYTES];
        //xor       = new XORCascade[ROUNDS][2*State.COLS];

        for(r=0; r<ROUNDS; r++){
            //
            // XOR state cascade
            //
            if (r<T1BOXES){
                xorState[r] = new XORCascadeState();
            }
            xorState2[r] = new XORCascadeState();
            xorState3[r] = new XORCascadeState();
            
            for(i=0; i<BYTES; i++){
                
                //
                // T1 boxes
                //
                if (r<T1BOXES){
                    t1[r][i] = new T1Box();
                }
                
                //
                // T2, T3 boxes
                //
                t2[r][i] = new T2Box();
                t3[r][i] = new T3Box();
                /*
                //
                // XOR cascade
                //
                if (i < 2*State.COLS){
                    xor[r][i] = new XORCascade();
                }*/
            }
        }
    }

    public T1Box[][] getT1() {
        return t1;
    }

    public XORCascadeState[] getXorState() {
        return xorState;
    }

    public T2Box[][] getT2() {
        return t2;
    }
    
    public XORCascadeState[] getXorState2() {
        return xorState2;
    }

    public T3Box[][] getT3() {
        return t3;
    }

    public XORCascadeState[] getXorState3() {
        return xorState3;
    }

    public boolean isEncrypt() {
        return encrypt;
    }

    public void setEncrypt(boolean encrypt) {
        this.encrypt = encrypt;
    }
    
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 89 * hash + Arrays.deepHashCode(this.t1);
        hash = 89 * hash + Arrays.deepHashCode(this.xorState);
        hash = 89 * hash + Arrays.deepHashCode(this.t2);
        hash = 89 * hash + Arrays.deepHashCode(this.t3);
        hash = 89 * hash + Arrays.deepHashCode(this.xorState3);
        hash = 89 * hash + (this.encrypt ? 1 : 0);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AES other = (AES) obj;
        if (!Arrays.deepEquals(this.t1, other.t1)) {
            return false;
        }
        if (!Arrays.deepEquals(this.xorState, other.xorState)) {
            return false;
        }
        if (!Arrays.deepEquals(this.t2, other.t2)) {
            return false;
        }
        if (!Arrays.deepEquals(this.t3, other.t3)) {
            return false;
        }
        if (!Arrays.deepEquals(this.xorState3, other.xorState3)) {
            return false;
        }
        if (this.encrypt != other.encrypt) {
            return false;
        }
        return true;
    }
}
