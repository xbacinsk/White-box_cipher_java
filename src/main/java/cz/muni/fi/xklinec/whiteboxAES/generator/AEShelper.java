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
package cz.muni.fi.xklinec.whiteboxAES.generator;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import cz.muni.fi.xklinec.whiteboxAES.AES;
import cz.muni.fi.xklinec.whiteboxAES.State;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;

/**
 * Contains basic AES constants and perform simple AES operations 
 * (SubByte, MixColumn, ShiftRows, AddRoundKey).
 * 
 * @author ph4r05
 */
public class AEShelper {
    public static final int POLYNOMIAL     = 0x11B;
    public static final int GENERATOR      = 0x03;
    public static final int DEGREE         = 8;
    public static final int AES_FIELD_SIZE = 1<<8;
    
    // TODO zmazat - len pre moje testovanie!
    public static final int vectX[][][] = new int[][][]{
    		{{0x14}, {0x31}, {0x1c}, {0x0f}}, {{0xeb}, {0xf1}, {0x01}, {0xd1}}, //0
    		{{0x20}, {0x97}, {0x1e}, {0xf1}}, {{0x79}, {0xa4}, {0xfd}, {0x4f}},
        
            {{0x32}, {0x43}, {0xf6}, {0xa8}}, {{0x88}, {0x5a}, {0x30}, {0x8d}}, //1
            {{0x31}, {0x31}, {0x98}, {0xa2}}, {{0xe0}, {0x37}, {0x07}, {0x34}},
            
            {{0x6b}, {0xc1}, {0xbe}, {0xe2}}, {{0x2e}, {0x40}, {0x9f}, {0x96}}, //2
            {{0xe9}, {0x3d}, {0x7e}, {0x11}}, {{0x73}, {0x93}, {0x17}, {0x2a}},
            
            {{0xae}, {0x2d}, {0x8a}, {0x57}}, {{0x1e}, {0x03}, {0xac}, {0x9c}}, //3
            {{0x9e}, {0xb7}, {0x6f}, {0xac}}, {{0x45}, {0xaf}, {0x8e}, {0x51}},
            
            {{0x30}, {0xc8}, {0x1c}, {0x46}}, {{0xa3}, {0x5c}, {0xe4}, {0x11}}, //4
            {{0xe5}, {0xfb}, {0xc1}, {0x19}}, {{0x1a}, {0x0a}, {0x52}, {0xef}},
            
            {{0xf6}, {0x9f}, {0x24}, {0x45}}, {{0xdf}, {0x4f}, {0x9b}, {0x17}}, //5
            {{0xad}, {0x2b}, {0x41}, {0x7b}}, {{0xe6}, {0x6c}, {0x37}, {0x10}},
    
            {{0x39}, {0x25}, {0x84}, {0x1d}}, {{0x02}, {0xdc}, {0x09}, {0xfb}}, //6
            {{0xdc}, {0x11}, {0x85}, {0x97}}, {{0x19}, {0x6a}, {0x0b}, {0x32}},
            
            {{0x3a}, {0xd7}, {0x7b}, {0xb4}}, {{0x0d}, {0x7a}, {0x36}, {0x60}}, //7
            {{0xa8}, {0x9e}, {0xca}, {0xf3}}, {{0x24}, {0x66}, {0xef}, {0x97}},
            
            {{0xf5}, {0xd3}, {0xd5}, {0x85}}, {{0x03}, {0xb9}, {0x69}, {0x9d}}, //8
            {{0xe7}, {0x85}, {0x89}, {0x5a}}, {{0x96}, {0xfd}, {0xba}, {0xaf}},
            
            {{0x43}, {0xb1}, {0xcd}, {0x7f}}, {{0x59}, {0x8e}, {0xce}, {0x23}}, //9
            {{0x88}, {0x1b}, {0x00}, {0xe3}}, {{0xed}, {0x03}, {0x06}, {0x88}},
            
            {{0x7b}, {0x0c}, {0x78}, {0x5e}}, {{0x27}, {0xe8}, {0xad}, {0x3f}}, //10
            {{0x82}, {0x23}, {0x20}, {0x71}}, {{0x04}, {0x72}, {0x5d}, {0xd4}},
            
            {{0x2b}, {0x7e}, {0x15}, {0x16}}, {{0x28}, {0xae}, {0xd2}, {0xa6}}, //11
            {{0xab}, {0xf7}, {0x15}, {0x88}}, {{0x09}, {0xcf}, {0x4f}, {0x3c}},
            
            {{0x60}, {0x3d}, {0xeb}, {0x10}}, {{0x15}, {0xca}, {0x71}, {0xbe}}, //12
            {{0x2b}, {0x73}, {0xae}, {0xf0}}, {{0x85}, {0x7d}, {0x77}, {0x81}},
            
            {{0x1f}, {0x35}, {0x2c}, {0x07}}, {{0x3b}, {0x61}, {0x08}, {0xd7}}, //13
            {{0x2d}, {0x98}, {0x10}, {0xa3}}, {{0x09}, {0x14}, {0xdf}, {0xf4}},
            
            {{0x75}, {0xeb}, {0xc2}, {0x7a}}, {{0xbf}, {0x12}, {0x85}, {0x7c}}, //14
            {{0x2f}, {0x1f}, {0x0a}, {0xee}}, {{0xcc}, {0x2d}, {0xfa}, {0x4c}},
            
            {{0x1b}, {0x95}, {0x4c}, {0xd7}}, {{0xdb}, {0x4b}, {0xac}, {0x52}}, //15
            {{0x2b}, {0x38}, {0xb0}, {0xd3}}, {{0xc9}, {0x19}, {0xad}, {0xfd}}
        };
    
    public static final int AES_TESTVECTORS = 4;
    public static final byte testVect128_key[] = new byte[]{
             (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
             (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88, (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c
    };

    public static final byte testVect128_plain[][] = new byte[][]{
            {(byte)0x32, (byte)0x43, (byte)0xf6, (byte)0xa8, (byte)0x88, (byte)0x5a, (byte)0x30, (byte)0x8d, 
             (byte)0x31, (byte)0x31, (byte)0x98, (byte)0xa2, (byte)0xe0, (byte)0x37, (byte)0x07, (byte)0x34},
            {(byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2, (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96, 
             (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a},
            {(byte)0xae, (byte)0x2d, (byte)0x8a, (byte)0x57, (byte)0x1e, (byte)0x03, (byte)0xac, (byte)0x9c, 
             (byte)0x9e, (byte)0xb7, (byte)0x6f, (byte)0xac, (byte)0x45, (byte)0xaf, (byte)0x8e, (byte)0x51},
            {(byte)0x30, (byte)0xc8, (byte)0x1c, (byte)0x46, (byte)0xa3, (byte)0x5c, (byte)0xe4, (byte)0x11, 
             (byte)0xe5, (byte)0xfb, (byte)0xc1, (byte)0x19, (byte)0x1a, (byte)0x0a, (byte)0x52, (byte)0xef},
            {(byte)0xf6, (byte)0x9f, (byte)0x24, (byte)0x45, (byte)0xdf, (byte)0x4f, (byte)0x9b, (byte)0x17, 
             (byte)0xad, (byte)0x2b, (byte)0x41, (byte)0x7b, (byte)0xe6, (byte)0x6c, (byte)0x37, (byte)0x10}
    };

    public static final byte testVect128_cipher[][] = new byte[][]{
            {(byte)0x39, (byte)0x25, (byte)0x84, (byte)0x1d, (byte)0x02, (byte)0xdc, (byte)0x09, (byte)0xfb, 
             (byte)0xdc, (byte)0x11, (byte)0x85, (byte)0x97, (byte)0x19, (byte)0x6a, (byte)0x0b, (byte)0x32},
            {(byte)0x3a, (byte)0xd7, (byte)0x7b, (byte)0xb4, (byte)0x0d, (byte)0x7a, (byte)0x36, (byte)0x60, 
             (byte)0xa8, (byte)0x9e, (byte)0xca, (byte)0xf3, (byte)0x24, (byte)0x66, (byte)0xef, (byte)0x97},
            {(byte)0xf5, (byte)0xd3, (byte)0xd5, (byte)0x85, (byte)0x03, (byte)0xb9, (byte)0x69, (byte)0x9d, 
             (byte)0xe7, (byte)0x85, (byte)0x89, (byte)0x5a, (byte)0x96, (byte)0xfd, (byte)0xba, (byte)0xaf},
            {(byte)0x43, (byte)0xb1, (byte)0xcd, (byte)0x7f, (byte)0x59, (byte)0x8e, (byte)0xce, (byte)0x23, 
             (byte)0x88, (byte)0x1b, (byte)0x00, (byte)0xe3, (byte)0xed, (byte)0x03, (byte)0x06, (byte)0x88},
            {(byte)0x7b, (byte)0x0c, (byte)0x78, (byte)0x5e, (byte)0x27, (byte)0xe8, (byte)0xad, (byte)0x3f, 
             (byte)0x82, (byte)0x23, (byte)0x20, (byte)0x71, (byte)0x04, (byte)0x72, (byte)0x5d, (byte)0xd4}
    };

    public static final byte testVect256_key[] = new byte[]{
             (byte)0x60, (byte)0x3d, (byte)0xeb, (byte)0x10, (byte)0x15, (byte)0xca, (byte)0x71, (byte)0xbe, 
             (byte)0x2b, (byte)0x73, (byte)0xae, (byte)0xf0, (byte)0x85, (byte)0x7d, (byte)0x77, (byte)0x81,
             (byte)0x1f, (byte)0x35, (byte)0x2c, (byte)0x07, (byte)0x3b, (byte)0x61, (byte)0x08, (byte)0xd7, 
             (byte)0x2d, (byte)0x98, (byte)0x10, (byte)0xa3, (byte)0x09, (byte)0x14, (byte)0xdf, (byte)0xf4
    };

    public static final byte testVect256_plain[][] = new byte[][]{
            {(byte)0x6b, (byte)0xc1, (byte)0xbe, (byte)0xe2, (byte)0x2e, (byte)0x40, (byte)0x9f, (byte)0x96, 
             (byte)0xe9, (byte)0x3d, (byte)0x7e, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2a},
            {(byte)0xae, (byte)0x2d, (byte)0x8a, (byte)0x57, (byte)0x1e, (byte)0x03, (byte)0xac, (byte)0x9c, 
             (byte)0x9e, (byte)0xb7, (byte)0x6f, (byte)0xac, (byte)0x45, (byte)0xaf, (byte)0x8e, (byte)0x51},
            {(byte)0x30, (byte)0xc8, (byte)0x1c, (byte)0x46, (byte)0xa3, (byte)0x5c, (byte)0xe4, (byte)0x11, 
             (byte)0xe5, (byte)0xfb, (byte)0xc1, (byte)0x19, (byte)0x1a, (byte)0x0a, (byte)0x52, (byte)0xef},
            {(byte)0xf6, (byte)0x9f, (byte)0x24, (byte)0x45, (byte)0xdf, (byte)0x4f, (byte)0x9b, (byte)0x17, 
             (byte)0xad, (byte)0x2b, (byte)0x41, (byte)0x7b, (byte)0xe6, (byte)0x6c, (byte)0x37, (byte)0x10}
    };

    public static final byte testVect256_cipher[][] = new byte[][]{
            {(byte)0xf3, (byte)0xee, (byte)0xd1, (byte)0xbd, (byte)0xb5, (byte)0xd2, (byte)0xa0, (byte)0x3c, 
             (byte)0x06, (byte)0x4b, (byte)0x5a, (byte)0x7e, (byte)0x3d, (byte)0xb1, (byte)0x81, (byte)0xf8},
            {(byte)0x59, (byte)0x1c, (byte)0xcb, (byte)0x10, (byte)0xd4, (byte)0x10, (byte)0xed, (byte)0x26, 
             (byte)0xdc, (byte)0x5b, (byte)0xa7, (byte)0x4a, (byte)0x31, (byte)0x36, (byte)0x28, (byte)0x70},
            {(byte)0xb6, (byte)0xed, (byte)0x21, (byte)0xb9, (byte)0x9c, (byte)0xa6, (byte)0xf4, (byte)0xf9, 
             (byte)0xf1, (byte)0x53, (byte)0xe7, (byte)0xb1, (byte)0xbe, (byte)0xaf, (byte)0xed, (byte)0x1d},
            {(byte)0x23, (byte)0x30, (byte)0x4b, (byte)0x7a, (byte)0x39, (byte)0xf9, (byte)0xf3, (byte)0xff, 
             (byte)0x06, (byte)0x7d, (byte)0x8d, (byte)0x8f, (byte)0x9e, (byte)0x24, (byte)0xec, (byte)0xc7}
    };
    
    // Reed-Solomon code matrix - for derivation of the key bytes needed for key-dependent S-boxes
    public static final byte rs[] = new byte[]{
        (byte)0x01, (byte)0xa4, (byte)0x55, (byte)0x87, (byte)0x5a, (byte)0x58, (byte)0xdb, (byte)0x9e, 
        (byte)0xa4, (byte)0x56, (byte)0x82, (byte)0xf3, (byte)0x1e, (byte)0xc6, (byte)0x68, (byte)0xe5,
        (byte)0x02, (byte)0xa1, (byte)0xfc, (byte)0xc1, (byte)0x47, (byte)0xae, (byte)0x3d, (byte)0x19, 
        (byte)0xa4, (byte)0x55, (byte)0x87, (byte)0x5a, (byte)0x58, (byte)0xdb, (byte)0x9e, (byte)0x01
    };
    
    // Substitution tables needed for key-dependent S-boxes
    protected static final byte q8x8[][]= new byte[][] {
    	{
    		(byte)0xA9, (byte)0x67, (byte)0xB3, (byte)0xE8, (byte)0x04, (byte)0xFD, (byte)0xA3, (byte)0x76, 
    		(byte)0x9A, (byte)0x92, (byte)0x80, (byte)0x78, (byte)0xE4, (byte)0xDD, (byte)0xD1, (byte)0x38, 
    		(byte)0x0D, (byte)0xC6, (byte)0x35, (byte)0x98, (byte)0x18, (byte)0xF7, (byte)0xEC, (byte)0x6C, 
    		(byte)0x43, (byte)0x75, (byte)0x37, (byte)0x26, (byte)0xFA, (byte)0x13, (byte)0x94, (byte)0x48, 
    		(byte)0xF2, (byte)0xD0, (byte)0x8B, (byte)0x30, (byte)0x84, (byte)0x54, (byte)0xDF, (byte)0x23, 
    		(byte)0x19, (byte)0x5B, (byte)0x3D, (byte)0x59, (byte)0xF3, (byte)0xAE, (byte)0xA2, (byte)0x82, 
    		(byte)0x63, (byte)0x01, (byte)0x83, (byte)0x2E, (byte)0xD9, (byte)0x51, (byte)0x9B, (byte)0x7C, 
    		(byte)0xA6, (byte)0xEB, (byte)0xA5, (byte)0xBE, (byte)0x16, (byte)0x0C, (byte)0xE3, (byte)0x61, 
    		(byte)0xC0, (byte)0x8C, (byte)0x3A, (byte)0xF5, (byte)0x73, (byte)0x2C, (byte)0x25, (byte)0x0B, 
    		(byte)0xBB, (byte)0x4E, (byte)0x89, (byte)0x6B, (byte)0x53, (byte)0x6A, (byte)0xB4, (byte)0xF1, 
    		(byte)0xE1, (byte)0xE6, (byte)0xBD, (byte)0x45, (byte)0xE2, (byte)0xF4, (byte)0xB6, (byte)0x66, 
    		(byte)0xCC, (byte)0x95, (byte)0x03, (byte)0x56, (byte)0xD4, (byte)0x1C, (byte)0x1E, (byte)0xD7, 
    		(byte)0xFB, (byte)0xC3, (byte)0x8E, (byte)0xB5, (byte)0xE9, (byte)0xCF, (byte)0xBF, (byte)0xBA, 
    		(byte)0xEA, (byte)0x77, (byte)0x39, (byte)0xAF, (byte)0x33, (byte)0xC9, (byte)0x62, (byte)0x71, 
    		(byte)0x81, (byte)0x79, (byte)0x09, (byte)0xAD, (byte)0x24, (byte)0xCD, (byte)0xF9, (byte)0xD8, 
    		(byte)0xE5, (byte)0xC5, (byte)0xB9, (byte)0x4D, (byte)0x44, (byte)0x08, (byte)0x86, (byte)0xE7, 
    		(byte)0xA1, (byte)0x1D, (byte)0xAA, (byte)0xED, (byte)0x06, (byte)0x70, (byte)0xB2, (byte)0xD2, 
    		(byte)0x41, (byte)0x7B, (byte)0xA0, (byte)0x11, (byte)0x31, (byte)0xC2, (byte)0x27, (byte)0x90, 
    		(byte)0x20, (byte)0xF6, (byte)0x60, (byte)0xFF, (byte)0x96, (byte)0x5C, (byte)0xB1, (byte)0xAB, 
    		(byte)0x9E, (byte)0x9C, (byte)0x52, (byte)0x1B, (byte)0x5F, (byte)0x93, (byte)0x0A, (byte)0xEF, 
    		(byte)0x91, (byte)0x85, (byte)0x49, (byte)0xEE, (byte)0x2D, (byte)0x4F, (byte)0x8F, (byte)0x3B, 
    		(byte)0x47, (byte)0x87, (byte)0x6D, (byte)0x46, (byte)0xD6, (byte)0x3E, (byte)0x69, (byte)0x64, 
    		(byte)0x2A, (byte)0xCE, (byte)0xCB, (byte)0x2F, (byte)0xFC, (byte)0x97, (byte)0x05, (byte)0x7A, 
    		(byte)0xAC, (byte)0x7F, (byte)0xD5, (byte)0x1A, (byte)0x4B, (byte)0x0E, (byte)0xA7, (byte)0x5A, 
    		(byte)0x28, (byte)0x14, (byte)0x3F, (byte)0x29, (byte)0x88, (byte)0x3C, (byte)0x4C, (byte)0x02, 
    		(byte)0xB8, (byte)0xDA, (byte)0xB0, (byte)0x17, (byte)0x55, (byte)0x1F, (byte)0x8A, (byte)0x7D, 
    		(byte)0x57, (byte)0xC7, (byte)0x8D, (byte)0x74, (byte)0xB7, (byte)0xC4, (byte)0x9F, (byte)0x72, 
    		(byte)0x7E, (byte)0x15, (byte)0x22, (byte)0x12, (byte)0x58, (byte)0x07, (byte)0x99, (byte)0x34, 
    		(byte)0x6E, (byte)0x50, (byte)0xDE, (byte)0x68, (byte)0x65, (byte)0xBC, (byte)0xDB, (byte)0xF8, 
    		(byte)0xC8, (byte)0xA8, (byte)0x2B, (byte)0x40, (byte)0xDC, (byte)0xFE, (byte)0x32, (byte)0xA4, 
    		(byte)0xCA, (byte)0x10, (byte)0x21, (byte)0xF0, (byte)0xD3, (byte)0x5D, (byte)0x0F, (byte)0x00, 
    		(byte)0x6F, (byte)0x9D, (byte)0x36, (byte)0x42, (byte)0x4A, (byte)0x5E, (byte)0xC1, (byte)0xE0
    	},
    	{
    		(byte)0x75, (byte)0xF3, (byte)0xC6, (byte)0xF4, (byte)0xDB, (byte)0x7B, (byte)0xFB, (byte)0xC8, 
    		(byte)0x4A, (byte)0xD3, (byte)0xE6, (byte)0x6B, (byte)0x45, (byte)0x7D, (byte)0xE8, (byte)0x4B, 
    		(byte)0xD6, (byte)0x32, (byte)0xD8, (byte)0xFD, (byte)0x37, (byte)0x71, (byte)0xF1, (byte)0xE1, 
    		(byte)0x30, (byte)0x0F, (byte)0xF8, (byte)0x1B, (byte)0x87, (byte)0xFA, (byte)0x06, (byte)0x3F, 
    		(byte)0x5E, (byte)0xBA, (byte)0xAE, (byte)0x5B, (byte)0x8A, (byte)0x00, (byte)0xBC, (byte)0x9D, 
    		(byte)0x6D, (byte)0xC1, (byte)0xB1, (byte)0x0E, (byte)0x80, (byte)0x5D, (byte)0xD2, (byte)0xD5, 
    		(byte)0xA0, (byte)0x84, (byte)0x07, (byte)0x14, (byte)0xB5, (byte)0x90, (byte)0x2C, (byte)0xA3, 
    		(byte)0xB2, (byte)0x73, (byte)0x4C, (byte)0x54, (byte)0x92, (byte)0x74, (byte)0x36, (byte)0x51, 
    		(byte)0x38, (byte)0xB0, (byte)0xBD, (byte)0x5A, (byte)0xFC, (byte)0x60, (byte)0x62, (byte)0x96, 
    		(byte)0x6C, (byte)0x42, (byte)0xF7, (byte)0x10, (byte)0x7C, (byte)0x28, (byte)0x27, (byte)0x8C, 
    		(byte)0x13, (byte)0x95, (byte)0x9C, (byte)0xC7, (byte)0x24, (byte)0x46, (byte)0x3B, (byte)0x70, 
    		(byte)0xCA, (byte)0xE3, (byte)0x85, (byte)0xCB, (byte)0x11, (byte)0xD0, (byte)0x93, (byte)0xB8, 
    		(byte)0xA6, (byte)0x83, (byte)0x20, (byte)0xFF, (byte)0x9F, (byte)0x77, (byte)0xC3, (byte)0xCC, 
    		(byte)0x03, (byte)0x6F, (byte)0x08, (byte)0xBF, (byte)0x40, (byte)0xE7, (byte)0x2B, (byte)0xE2, 
    		(byte)0x79, (byte)0x0C, (byte)0xAA, (byte)0x82, (byte)0x41, (byte)0x3A, (byte)0xEA, (byte)0xB9, 
    		(byte)0xE4, (byte)0x9A, (byte)0xA4, (byte)0x97, (byte)0x7E, (byte)0xDA, (byte)0x7A, (byte)0x17, 
    		(byte)0x66, (byte)0x94, (byte)0xA1, (byte)0x1D, (byte)0x3D, (byte)0xF0, (byte)0xDE, (byte)0xB3, 
    		(byte)0x0B, (byte)0x72, (byte)0xA7, (byte)0x1C, (byte)0xEF, (byte)0xD1, (byte)0x53, (byte)0x3E, 
    		(byte)0x8F, (byte)0x33, (byte)0x26, (byte)0x5F, (byte)0xEC, (byte)0x76, (byte)0x2A, (byte)0x49, 
    		(byte)0x81, (byte)0x88, (byte)0xEE, (byte)0x21, (byte)0xC4, (byte)0x1A, (byte)0xEB, (byte)0xD9, 
    		(byte)0xC5, (byte)0x39, (byte)0x99, (byte)0xCD, (byte)0xAD, (byte)0x31, (byte)0x8B, (byte)0x01, 
    		(byte)0x18, (byte)0x23, (byte)0xDD, (byte)0x1F, (byte)0x4E, (byte)0x2D, (byte)0xF9, (byte)0x48, 
    		(byte)0x4F, (byte)0xF2, (byte)0x65, (byte)0x8E, (byte)0x78, (byte)0x5C, (byte)0x58, (byte)0x19, 
    		(byte)0x8D, (byte)0xE5, (byte)0x98, (byte)0x57, (byte)0x67, (byte)0x7F, (byte)0x05, (byte)0x64, 
    		(byte)0xAF, (byte)0x63, (byte)0xB6, (byte)0xFE, (byte)0xF5, (byte)0xB7, (byte)0x3C, (byte)0xA5, 
    		(byte)0xCE, (byte)0xE9, (byte)0x68, (byte)0x44, (byte)0xE0, (byte)0x4D, (byte)0x43, (byte)0x69, 
    		(byte)0x29, (byte)0x2E, (byte)0xAC, (byte)0x15, (byte)0x59, (byte)0xA8, (byte)0x0A, (byte)0x9E, 
    		(byte)0x6E, (byte)0x47, (byte)0xDF, (byte)0x34, (byte)0x35, (byte)0x6A, (byte)0xCF, (byte)0xDC, 
    		(byte)0x22, (byte)0xC9, (byte)0xC0, (byte)0x9B, (byte)0x89, (byte)0xD4, (byte)0xED, (byte)0xAB, 
    		(byte)0x12, (byte)0xA2, (byte)0x0D, (byte)0x52, (byte)0xBB, (byte)0x02, (byte)0x2F, (byte)0xA9, 
    		(byte)0xD7, (byte)0x61, (byte)0x1E, (byte)0xB4, (byte)0x50, (byte)0x04, (byte)0xF6, (byte)0xC2, 
    		(byte)0x16, (byte)0x25, (byte)0x86, (byte)0x56, (byte)0x55, (byte)0x09, (byte)0xBE, (byte)0x91
    		}
    };
    
    protected GF2mField field;
    protected int g[]             = new int[AES_FIELD_SIZE];
    protected int gInv[]          = new int[AES_FIELD_SIZE];
    protected int sbox[]          = new int[AES_FIELD_SIZE];
    protected int sboxAffine[]    = new int[AES_FIELD_SIZE];
    protected int sboxAffineInv[] = new int[AES_FIELD_SIZE];
    
    // 10 = number of rounds (+1) for 128bit key
	int s0_k0_k1[][] = new int[10][AES_FIELD_SIZE];
	int s1_k2_k3[][] = new int[10][AES_FIELD_SIZE];
	int s2_k4_k5[][] = new int[10][AES_FIELD_SIZE];
	int s3_k6_k7[][] = new int[10][AES_FIELD_SIZE];
	int s0_k0_k1_inv[][] = new int[10][AES_FIELD_SIZE];
	int s1_k2_k3_inv[][] = new int[10][AES_FIELD_SIZE];
	int s2_k4_k5_inv[][] = new int[10][AES_FIELD_SIZE];
	int s3_k6_k7_inv[][] = new int[10][AES_FIELD_SIZE];
	
	// MDS matrix is involutory, so the same for encryption and decryption
	protected int MDS16x16[][] = new int[16][16];
	protected GF2mMatrixEx MDS16x16Mat;
	protected GF2mMatrixEx MDS16x16Mat_array[] = new GF2mMatrixEx[AES.ROUNDS-1];
	
    protected int mixColModulus[]      = new int[5];
    protected int mixColMultiply[]     = new int[4];
    protected int mixColMultiplyInv[]  = new int[4];
    
    public static final int RCNUM = 16;
    protected int RC[] = new int[RCNUM];
    protected GF2mMatrixEx mixColMat;
    protected GF2mMatrixEx mixColInvMat;
    
    /**
     * Initializes AES constans (S-box, T-box, RC for key schedule).
     * 
     * @param encrypt 
     */
    public void build(boolean encrypt){
        field = new GF2mField(8, POLYNOMIAL);
        System.out.println(field);
        
        int i,c,cur = 1;
		gInv[0] = -1;
		for(i=0; i<AES_FIELD_SIZE; i++){
	            g[i] = cur;
	            gInv[cur] = i;
	            cur = field.mult(cur, GENERATOR);
		}
	        
	        // 2. compute GF(256) element inverses in terms of generator exponent
		sbox[0] = -1;
		for(i=1; i<AES_FIELD_SIZE; i++){
	            sbox[i] = 255-i;
		}
	        
	        GF2MatrixEx tmpM = new GF2MatrixEx(8, 1);
	        GF2MatrixEx afM  = getDefaultAffineMatrix(true);
	        byte        afC  = getDefaultAffineConstByte(true);
	        
	        
	        // Computing whole Sboxes with inversion + affine transformation in generic AES
	        // Normal Sbox:      S(x) = const    +   A(x^{-1})
		// Sbox in Dual AES: G(x) = T(const) + T(A(T^{-1}(x^{-1})))
		for(i=0; i<AES_FIELD_SIZE; i++){
	            int tmpRes;
	
	            // i is now long representation, gInv transforms it to exponent power to obtain inverse.
	            // Also getLong(g[gInv[i]]) == i
	            int transValue = i==0 ? 0 : g[255-gInv[i]];
	
	            // tmpM = col vector of transValue
	            NTLUtils.zero(tmpM);
	            NTLUtils.putByteAsColVector(tmpM, (byte)transValue, 0, 0);
	            
	            // const + A(x^{-1})
	            GF2MatrixEx resMatrix = (GF2MatrixEx) afM.rightMultiply(tmpM);
	            tmpRes = (byte) field.add(NTLUtils.colBinaryVectorToByte(resMatrix, 0, 0), afC) & 0xff;
	
	
	            // S-box was created here, key-dependent S-boxes must be created before this function call
	            //sboxAffine[i] = tmpRes; //will be deleted
	            //sboxAffineInv[tmpRes] = i; //will be deleted
	
	
	            // Inversion, idea is the same, i is the long representation of element in GF, apply inverted affine transformation and take inverse
	            // Ax^{-1} + c is input to this transformation
	            //              [A^{-1} * (A{x^-1} + c) + d]^{-1} is this transformation;
	            // correctness: [A^{-1} * (Ax^-1   + c) + d]^{-1} =
	            //				[A^{-1}Ax^{-1} + A^{-1}c + d]^{-1} =	//	A^{-1}c = d
	            //				[x^{-1}        + 0]^{-1} =
	            //				x
	            //
	            // Computation is useless, we have inversion of transformation right from transformation above
	            // by simply swapping indexes. This is just for validation purposes to show, that it really works and how
		}
				
		
		createMDS16x16();
		MDS16x16Mat = new GF2mMatrixEx(field, 16, 16);
		for(i=0; i<16; i++){
	        for(c=0; c<16; c++){
	        	MDS16x16Mat.set(i, c, MDS16x16[i][c]);
	        }
		}
		//TODO zrusit MixColumn
///*
		// 6. MixColumn operations
		// modulus x^4 + 1
		mixColModulus[0] = g[0];
		mixColModulus[4] = g[0];
	
		// 03 x^3 + 01 x^2 + 01 x + 02
		mixColMultiply[0] = g[25];
		mixColMultiply[1] = g[0];
		mixColMultiply[2] = g[0];
		mixColMultiply[3] = g[1];
	
		// inverse polynomial
		mixColMultiplyInv[0] = g[223];
		mixColMultiplyInv[1] = g[199];
		mixColMultiplyInv[2] = g[238];
		mixColMultiplyInv[3] = g[104];
	
		// MixCols multiplication matrix based on mult polynomial -  see Rijndael description of this.
		// Polynomials have coefficients in GF(256).
		mixColMat    = new GF2mMatrixEx(field, 4, 4);
	        mixColInvMat = new GF2mMatrixEx(field, 4, 4);
		for(i=0; i<4; i++){
	            for(c=0; c<4; c++){
	                mixColMat.set(i, c, mixColMultiply[(i+4-c) % 4]);
	                mixColInvMat.set(i, c, mixColMultiplyInv[(i+4-c) % 4]);
	            }
		}
//*/

		// Round key constant RC (for key schedule) obeys this reccurence:
		// RC[0] = 1
		// RC[i] = '02' * RC[i-1] = x * RC[i-1] = x^{i-1} `mod` R(X)
		RC[0] = g[0];
		for(i=1; i<RCNUM; i++){
			RC[i] = field.mult(g[25], RC[i-1]);
		}
    }
    
    /**
     * Number of rounds of AES depends on key size
     */
    public static int getNumberOfRounds(int keySize){ 
        return keySize/4+6; 
    }
    
    /**
     * Positive modulo 4
     * @param a
     * @return 
     */
    public static int mod4(int a){ 
        int c = a % 4; 
        return c<0 ? c+4 : c; 
    }
    
    /**
     * Returns default affine matrix transformation for S-box.
     * @param encrypt
     * @return 
     */
    public static GF2MatrixEx getDefaultAffineMatrix(boolean encrypt){
        GF2MatrixEx r = new GF2MatrixEx(8, 8);
        
        if (encrypt){
            NTLUtils.putByteAsRowVector(r, (byte)0x8F, 0, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0xC7, 1, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0xE3, 2, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0xF1, 3, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0xF8, 4, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x7C, 5, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x3E, 6, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x1F, 7, 0);
        } else {
            NTLUtils.putByteAsRowVector(r, (byte)0x25, 0, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x92, 1, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x49, 2, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0xA4, 3, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x52, 4, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x29, 5, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x94, 6, 0);
            NTLUtils.putByteAsRowVector(r, (byte)0x4A, 7, 0);         
        }
        
        return r;
    }
    
    /**
     * Default affine constant for affine transformation for S-box.
     * @param encrypt
     * @return 
     */
    public static byte getDefaultAffineConstByte(boolean encrypt){
        return encrypt ? (byte)0x63 : (byte)0x05;
    }
    
    /**
     * Returns affine constant for affine transformation for S-box as a col vector.
     * @param encrypt
     * @return 
     */
    public static GF2MatrixEx getDefaultAffineConst(boolean encrypt){
        GF2MatrixEx r = new GF2MatrixEx(8,1);
        NTLUtils.putByteAsColVector(r, getDefaultAffineConstByte(encrypt), 0, 0);
        return r;
    }
    
    /**
     * Returns number of all round keys together. 
     * 
     * @param keySize
     * @return 
     */
    public static int getRoundKeysSize(int keySize){
        return (4 * State.COLS * (getNumberOfRounds(keySize) + 1));
    }
    
    /**
     * AES key schedule.
     * 
     * @param roundKeys
     * @param key
     * @param keySize 
     */
    public byte[] keySchedule(byte[] key, int size, boolean debug){
        /* current expanded keySize, in bytes */
	int currentSize = 0;
	int rconIteration = 0;
	int i,j;
	int roundKeysSize = getRoundKeysSize(size);

	byte tmp;
        byte[] t = new byte[4]; //vec_GF2E t(INIT_SIZE, 4);
        byte[] roundKeys = new byte[roundKeysSize];
        if (debug) {
            System.out.println("Expanded key size will be: " + roundKeysSize);
        }

        /* set the 16,24,32 bytes of the expanded key to the input key */
        for (i = 0; i < size; i++) {
            roundKeys[i] = key[i];
        }

        currentSize += size;
        while (currentSize < roundKeysSize) {
            if (debug) {
                System.out.println("CurrentSize: " + currentSize + "; expandedKeySize: " + roundKeysSize);
            }

            /* assign the previous 4 bytes to the temporary value t */
            for (i = 0; i < 4; i++) {
                t[i] = roundKeys[(currentSize - 4) + i];
            }

            /**
             * every 16,24,32 bytes we apply the core schedule to t and
             * increment rconIteration afterwards
             */
            if (currentSize % size == 0) {
                //core(t, rconIteration++);
		/* rotate the 32-bit word 8 bits to the left */
                tmp = t[0];
                t[0] = t[1];
                t[1] = t[2];
                t[2] = t[3];
                t[3] = tmp;
                /* apply S-Box substitution on all 4 parts of the 32-bit word */
                for (j = 0; j < 4; ++j) {
                    if (debug) {
                        System.out.println("Sboxing key t[" + j
                                + "]=" + t[j]
                                + "=" + NTLUtils.chex(t[j])
                                + "; sboxval: " + NTLUtils.chex(sboxAffine[t[j]]));
                    }

                    // Apply S-box to t[j]
                    t[j] = (byte) (sboxAffine[t[j] & 0xff] & 0xff);

                    if (debug) {
                        System.out.println(" after Sbox = " + t[j] + "=" + NTLUtils.chex(t[j]));
                    }
                }
                
                /* XOR the output of the rcon operation with i to the first part (leftmost) only */
                t[0] = (byte) ((byte) field.add(t[0], RC[rconIteration++]) & 0xff);

                if (debug) {
                    System.out.println("; after XOR with RC[" + NTLUtils.chex(RC[rconIteration - 1]) + "] = " + t[0] + " = " + NTLUtils.chex(t[0]));
                }
            }

            /* For 256-bit keys, we add an extra sbox to the calculation */
            if (size == 32 && ((currentSize % size) == 16)) {
                for (i = 0; i < 4; i++) {
                    t[i] = (byte) (sboxAffine[t[i] & 0xff] & 0xff);
                }
            }
            
            /* We XOR t with the four-byte block 16,24,32 bytes before the new expanded key.
             * This becomes the next four bytes in the expanded key.
             */
            for (i = 0; i < 4; i++) {
                roundKeys[currentSize] = (byte) ((byte) field.add(roundKeys[currentSize - size], t[i]) & 0xff);

                if (debug) {
                    System.out.println("t[" + i + "] = " + NTLUtils.chex(t[i]));
                }

                currentSize++;
            }
        }

        return roundKeys;
    }
    
    /**
     * Hash chain using scrypt - only for 128-bit keys (AES.ROUNDS is set to 10).
     * Used instead of the reversible Rijndael Key Schedule.
     * 
     * @param key
     * @param size
     * @param debug
     * @return
     */
    public byte[] hashChain(byte[] key, int size, String saltString, boolean debug) {
    	
    	int currentSize = 0;
    	int i;
    	int roundKeysSize = getRoundKeysSize(size);
    	int roundsNum = getNumberOfRounds(size);
    	    	
    	byte[] roundKeys = new byte[roundKeysSize];
    	byte[] tmpKey = new byte[size];
    	byte[] salt = saltString.getBytes();
    	
    	System.arraycopy(key, 0, tmpKey, 0, size);
    	
    	for(i = 0; i < roundsNum + 1; i++) {
    		
    		if(i == 0)
    			//tmpKey = SCrypt.generate(key, salt, 16, 1, 1, size);
    			tmpKey = hashFunction(key, salt, size, AES.scrypt_N, AES.scrypt_r, AES.scrypt_p, 16);
    		else {
	    		byte[] hashInput = new byte[2*size];
	    		System.arraycopy(tmpKey, 0, hashInput, 0, size);
	    		System.arraycopy(key, 0, hashInput, size, size);
	    		
	    		//tmpKey = SCrypt.generate(hashInput, salt, 16, 1, 1, size);
	    		tmpKey = hashFunction(hashInput, salt, size, AES.scrypt_N, AES.scrypt_r, AES.scrypt_p, 16);
    		}
    		
    		System.arraycopy(tmpKey, 0, roundKeys, currentSize, size);
    		currentSize += size;
    	}
    	return roundKeys;
    }
    
    /**
     * Hash function with SHA256 applied on the input.
     * 
     * @param input
     * @param salt
     * @param size size of the output
     * @param n_bc work load for bcrypt - for now not used
     * @param n_sha number of sha256 applications
     * @return
     */
    private byte[] hashFunction(byte[] input, byte[] salt, int size, int sc_N, int sc_r, int sc_p, int n_sha) {
    	int i;
    	byte[] tmpInput = new byte[input.length];
    	System.arraycopy(input, 0, tmpInput, 0, input.length);
    	
    	for(i = 0; i < n_sha; i++) {
    		try {
	    		MessageDigest md = MessageDigest.getInstance("SHA-256"); //SHA256 in Dusan's thesis
	    		md.update(tmpInput);
	    		tmpInput = md.digest();
    		} catch(Exception e) { //NoSuchAlgorithmException
    			System.out.println("Problem with SHA256 in hashFunction (used in hashChain).");
    		}
    	}
    	
    	return SCrypt.generate(tmpInput, salt, sc_N, sc_r, sc_p, size);
    }
    
    /**
     * Key-dependent (Twofish) S-boxes (and their inversions) - only for 128-bit keys (AES.ROUNDS is set to 10).
     * 
     * @param key
     * @param size size of the given key
     * @return
     */
    public void createKeyDependentSboxes(byte[] key, int size) {
    	int i, r;
    	
    	byte[] magicConstant = AES.SBOXconstant;
    	byte[] input = new byte[key.length + magicConstant.length];
    	System.arraycopy(key, 0, input, 0, key.length);
    	System.arraycopy(magicConstant, 0, input, key.length, magicConstant.length);
    	
        byte[] roundKeysForSboxes = hashChain(input, size, AES.SALT, false);
    	
    	for(r = 0; r<roundKeysForSboxes.length/size-1; r++) {
    		
    		byte[] roundKey = new byte[size];
    		System.arraycopy(roundKeysForSboxes, size*r, roundKey, 0, size);

        	byte[] key_bytesForSboxes = keyBytesDerivation(roundKey);

	    	for(i = 0; i<256; i++) {
		    	
		    	s0_k0_k1[r][i] = sboxgen(0,13,i,key_bytesForSboxes);
		    	s1_k2_k3[r][i] = sboxgen(1,13,i,key_bytesForSboxes);
		    	s2_k4_k5[r][i] = sboxgen(2,13,i,key_bytesForSboxes);
		    	s3_k6_k7[r][i] = sboxgen(3,13,i,key_bytesForSboxes);

		    	s0_k0_k1_inv[9-r][s0_k0_k1[r][i]] = i;
		    	s1_k2_k3_inv[9-r][s1_k2_k3[r][i]] = i;
		    	s2_k4_k5_inv[9-r][s2_k4_k5[r][i]] = i;
		    	s3_k6_k7_inv[9-r][s3_k6_k7[r][i]] = i;
	    	}
    	}
    }
    
    /**
     * Derivation of the exact key bytes for key-dependent S-boxes (according to [Twofish: A 128-Bit Block Cipher])
     * 
     * @param key original key
     * @param keySize size of the given key (in bytes)
     */
    private byte[][] keyBytesDerivation(byte[] key, int keySize) {
    	int i, m, j;
    	byte s[][] = new byte[keySize/8][4];
    	
    	for(i = 0; i<keySize/8; i++) {
    		for(m = 0; m<8; m++) {
    			for(j = 0; j<4; j++) {
    				s[i][j] += (rs[8*j+m] & 0xff) * (key[8*i+m] & 0xff);
    			}
    		}
    	}
    	return s;
    }
    
    /**
     * Derivation of the exact key bytes for key-dependent S-boxes using SHA512
     * 
     * @param key original key
     */
    private byte[] keyBytesDerivation(byte[] key) {

    	byte s[] = new byte[64];
    	
		try {
    		MessageDigest md = MessageDigest.getInstance("SHA-512");
    		md.update(key);
    		s = md.digest();
		} catch(Exception e) { //NoSuchAlgorithmException
			System.out.println("Problem with SHA512 in keyBytesDerivation (used in createKeyDependentSboxes).");
		}
		
    	return s;
    }
    
    private int sboxgen(int j, int l, int x, byte[] key_bytes) {
    	
    	int qs[][] = new int[][] {{0,0,1,0,1,0,1,0,1,0,1,0,1,1},
    							  {1,0,0,1,1,0,0,1,1,0,0,1,1,0},
    							  {0,1,1,0,0,1,1,0,0,1,1,0,0,1},
    							  {1,1,0,0,0,1,1,1,0,0,0,1,1,1}};
    	
    	if(l == 0)
    		return (int)q8x8[qs[j][0]][x] & 0xff;
    	else
    		return (int)q8x8[qs[j][l]][sboxgen(j, l-1, x, key_bytes) ^ ((int)key_bytes[4*(l-1)+j] & 0xff)] & 0xff;
    }
    
    /**
     * Key-dependent S-boxes on one byte.
     * 
     * @param e
     * @param round
     * @param column
     * @return
     */
    public int ByteSub(int e, int round, int column) {
        
    	switch(column) {
    		case 0: return s0_k0_k1[round][AES.posIdx(e)];
    		case 1: return s1_k2_k3[round][AES.posIdx(e)];
    		case 2: return s2_k4_k5[round][AES.posIdx(e)];
    		case 3: return s3_k6_k7[round][AES.posIdx(e)];   	
    	}
    	return 0; //TODO skontrolovat, ci sa to niekedy nestane
    }
    
    /**
     * Key-dependent S-boxes on one byte.
     * 
     * @param e
     * @param round
     * @param column
     * @return 
     */
    public int ByteSubInv(int e, int round, int column) {
        
    	switch(column) {
    		case 0: return s0_k0_k1_inv[round][AES.posIdx(e)];
    		case 1: return s1_k2_k3_inv[round][AES.posIdx(e)];
    		case 2: return s2_k4_k5_inv[round][AES.posIdx(e)];
    		case 3: return s3_k6_k7_inv[round][AES.posIdx(e)];   	
    	}
    	return 0; //TODO skontrolovat, ci sa to niekedy nestane
    }
    

    /**
     * AES S-box.
     * @param e
     * @return 
     */
    public int ByteSub(int e){
        return sboxAffine[AES.posIdx(e)];
    }

    /**
     * AES S-box on whole state array.
     * @param state 
     */
    public void ByteSub(State state) {
        int i, j;
        for (i = 0; i < State.ROWS; i++) {
            for (j = 0; j < State.COLS; j++) {
                state.set((byte) sboxAffine[state.get(i, j)], i, j);
            }
        }
    }

    /**
     * AES S-box inverse.
     * @param e
     * @return 
     */
    public int ByteSubInv(int e){
        return sboxAffineInv[AES.posIdx(e)];
    }

    /**
     * AES S-box inverse on whole state array.
     * @param state 
     */
    public void ByteSubInv(State state){
        int i, j;
        for (i = 0; i < State.ROWS; i++) {
            for (j = 0; j < State.COLS; j++) {
                state.set((byte) sboxAffineInv[state.get(i, j)], i, j);
            }
        }
    }

    /**
     * Adds specified round key to state array.
     * @param state
     * @param expandedKey
     * @param offset 
     */
    public void AddRoundKey(State state, byte[] expandedKey, int offset){
        int i,j;
        for(i=0; i<State.ROWS; i++){
            for(j=0; j<State.COLS; j++){
                state.set((byte) field.add(state.get(i, j), expandedKey[offset + j*4+i]) , i, j);
            }
        }
    }

    /**
     * Shift Rows operation on state array, in-place.
     * @param state 
     */
    public void ShiftRows(State state) {
        // 1. row = no shift. 2. row = cyclic shift to the left by 1
        // for AES with Nb=4, left shift for rows are: 1=1, 2=2, 3=3.
        byte tmp;
        int i, j;
        for (i = 1; i < State.ROWS; i++) {
            for (j = 1; j <= i; j++) {
                tmp = state.get(i, 0);
                state.set(state.get(i, 1), i, 0);
                state.set(state.get(i, 2), i, 1);
                state.set(state.get(i, 3), i, 2);
                state.set(tmp, i, 3);
            }
        }
    }

    /**
     * Inverse of Shift Rows operation on state array, in-place.
     * @param state 
     */
    public void ShiftRowsInv(State state) {
        // 1. row = no shift. 2. row = cyclic shift to the left by 1
        // for AES with Nb=4, left shift for rows are: 1=1, 2=2, 3=3.
        byte tmp;
        int i, j;
        for (i = 1; i < State.ROWS; i++) {
            for (j = 1; j <= i; j++) {
                tmp = state.get(i, 3);
                state.set(state.get(i, 2), i, 3);
                state.set(state.get(i, 1), i, 2);
                state.set(state.get(i, 0), i, 1);
                state.set(tmp, i, 0);
            }
        }
    }

    /*
     * TODO the permutation functions should be MACROs?
     */

    private int[] permutationMDS(int[] inputRow, int par) {
    	int i,j;
    	int par2 = par/2;
    	int rowLength = inputRow.length;
    	int[] outputRow = new int[rowLength];
    	
    	for(i = 0; i<rowLength; i+=par) {
    		for(j = 0; j<par2; j++) {
        		outputRow[i+j] = inputRow[i+j+par2];
        		outputRow[i+j+par2] = inputRow[i+j];
    		}
    	}

    	return outputRow;
    }
    
    /**
     * Independent MDS16x16 matrix
     */
	public void createMDS16x16() {
		int i;
		int firstRow[] = new int[] { //last byte is computed from previous 15 using XOR through all of them and 0x01
			0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x10, 0x02, 0x1e
		}; //what is better: byte or int?
		
		MDS16x16[0] = firstRow;
		MDS16x16[2] = permutationMDS(MDS16x16[0], 4);
		MDS16x16[4] = permutationMDS(MDS16x16[0], 8);
		MDS16x16[6] = permutationMDS(MDS16x16[2], 8);
		MDS16x16[8] = permutationMDS(MDS16x16[0], 16);
		MDS16x16[10] = permutationMDS(MDS16x16[8], 4);
		MDS16x16[12] = permutationMDS(MDS16x16[8], 8);
		MDS16x16[14] = permutationMDS(MDS16x16[10], 8);
		
		for(i = 0; i<16; i+=2)
			MDS16x16[i+1] = permutationMDS(MDS16x16[i], 2);
	}
	
	//TODO a better solution for this
    private boolean contains(final int[] array, final int key) {
        for (final int i : array) {
            if (i == key) {
                return true;
            }
        }
        return false;
    }
	
	/**
	 * Key-dependent MDS16x16 matrix.
	 * 
	 * @param key
	 */
	public int[][] createMDS16x16(byte[] key, boolean debug) {
		int i;
		int firstRow[] = new int[16]; //must be created cleverly - key byte not 0, pairwise different
		
		Set<Integer> set = new LinkedHashSet<Integer>();
		for(i = 0; i<16; i++) {
			set.add((key[i] & 0x3f)); //TODO smaller numbers (5 bits)? I think 6 bits is a good compromise
			set.add(((key[i] >>> 2) & 0x3f));
		}

		firstRow[15] = 0; //here will be XOR of previous 15 bytes and 1
		int firstRow15tmp = 1;
		i = 0;
		for(Integer m : set){
			firstRow[i] = m;
			firstRow15tmp ^= firstRow[i];
			if(i == 14 && (contains(firstRow, firstRow15tmp) || firstRow15tmp == 0)) {
				firstRow15tmp ^= firstRow[i];
				continue;
			}
			if(m != 0) i++;
			if(i == 15) {
				firstRow[15] = firstRow15tmp;
				break;
			}
		}

		if(debug) {
			for(int g = 0; g<16; g++)
				System.out.print(firstRow[g] + " ");
			System.out.println(",");
		}
	
		if(i<15) {
			if(debug) System.out.println("Constant MDS matrix used.");
			return null;
		}
		
		int MDS16x16D[][] = new int[16][16];
		
		MDS16x16D[0] = firstRow;
		MDS16x16D[2] = permutationMDS(MDS16x16D[0], 4);
		MDS16x16D[4] = permutationMDS(MDS16x16D[0], 8);
		MDS16x16D[6] = permutationMDS(MDS16x16D[2], 8);
		MDS16x16D[8] = permutationMDS(MDS16x16D[0], 16);
		MDS16x16D[10] = permutationMDS(MDS16x16D[8], 4);
		MDS16x16D[12] = permutationMDS(MDS16x16D[8], 8);
		MDS16x16D[14] = permutationMDS(MDS16x16D[10], 8);
		
		for(i = 0; i<16; i+=2)
			MDS16x16D[i+1] = permutationMDS(MDS16x16D[i], 2);
		
		return MDS16x16D;
	}
	
	/**
	 * TODO different key schedule than round keys, like for S-boxes
	 * Generates MDS matrices from the given key schedule - one matrix per round
	 * 
	 * @param keySchedule
	 * @param encrypt when decrypting, matrices are generated in reverse order
	 */
	public void generateKeyDependentMDSmatrices(byte[] key, int size, boolean encrypt, boolean debug) {
		
    	byte[] magicConstant = AES.MDSconstant;
    	byte[] input = new byte[key.length + magicConstant.length];
    	System.arraycopy(key, 0, input, 0, key.length);
    	System.arraycopy(magicConstant, 0, input, key.length, magicConstant.length);
    	
        byte[] roundKeysForMDSmatrices = hashChain(input, size, AES.SALT, false);
    	
		byte roundKey[] = new byte[16];
		for(int i = 0; i<AES.ROUNDS-1; i++) {
			System.arraycopy(roundKeysForMDSmatrices, 16*i, roundKey, 0, 16);
			if(encrypt)
				MDS16x16Mat_array[i] = generateKeyDependentMDSmatrix(roundKey, debug);
			else 
				MDS16x16Mat_array[8-i] = generateKeyDependentMDSmatrix(roundKey, debug);
		}
	}
	
	/**
	 * Generates MDS matrix from the given (round)key.
	 * If key is not suitable for matrix generation, constant MDS16x16Mat (created in build method) is returned
	 * 
	 * @param key
	 * @return
	 */
	public GF2mMatrixEx generateKeyDependentMDSmatrix(byte[] key, boolean debug) {
		int MDS16x16D[][] = createMDS16x16(key, debug);
		if(MDS16x16D == null) return MDS16x16Mat;
		
		GF2mMatrixEx MDS16x16MatD = new GF2mMatrixEx(field, 16, 16);
		for(int i=0; i<16; i++){
	        for(int c=0; c<16; c++){
	        	MDS16x16MatD.set(i, c, MDS16x16D[i][c]);
	        }
		}
		return MDS16x16MatD;
	}


    /**
     * MixColumn operation on all columns on state matrix.
     * @param state 
     */
    public void MixColumn(State state) {
        int i, j;
        GF2mMatrixEx resMat;
        GF2mMatrixEx tmpMat = new GF2mMatrixEx(field, 4, 1);

        for (i = 0; i < State.COLS; i++) {
            // copy i-th column to 4*1 matrix - for multiplication
            for (j = 0; j < State.ROWS; j++) {
                tmpMat.set(j, 0, state.get(j, i));
            }

            resMat = mixColMat.rightMultiply(tmpMat);

            // copy result back to i-th column
            for (j = 0; j < State.ROWS; j++) {
                state.set((byte) resMat.get(j, 0), j, i);
            }
        }
    }

    /**
     * Inverse MixColumn operation on all columns on state matrix.
     * @param state 
     */
    public void MixColumnInv(State state){
        int i,j;
        GF2mMatrixEx resMat;
        GF2mMatrixEx tmpMat = new GF2mMatrixEx(field, 4, 1);

        for (i = 0; i < State.COLS; i++) {
            // copy i-th column to 4*1 matrix - for multiplication
            for (j = 0; j < State.ROWS; j++) {
                tmpMat.set(j, 0, state.get(j, i));
            }

            resMat = mixColInvMat.rightMultiply(tmpMat);

            // copy result back to i-th column
            for (j = 0; j < State.ROWS; j++) {
                state.set((byte) resMat.get(j, 0), j, i);
            }
        }
    }

    public GF2mField getField() {
        return field;
    }

    public int[] getG() {
        return g;
    }

    public int[] getgInv() {
        return gInv;
    }

    public int[] getSbox() {
        return sbox;
    }

    public int[] getSboxAffine() {
        return sboxAffine;
    }

    public int[] getSboxAffineInv() {
        return sboxAffineInv;
    }
    
	public int[][] getMDS16x16() {
		return MDS16x16;
	}
	
	public GF2mMatrixEx getMDS16x16Mat() {
		return MDS16x16Mat;
	}
	
	public GF2mMatrixEx[] getMDS16x16Mat_array() {
		return MDS16x16Mat_array;
	}

    public int[] getMixColModulus() {
        return mixColModulus;
    }

    public int[] getMixColMultiply() {
        return mixColMultiply;
    }

    public int[] getMixColMultiplyInv() {
        return mixColMultiplyInv;
    }

    public int[] getRC() {
        return RC;
    }

    public GF2mMatrixEx getMixColMat() {
        return mixColMat;
    }

    public GF2mMatrixEx getMixColInvMat() {
        return mixColInvMat;
    }
}
