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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cz.muni.fi.xklinec.whiteboxAES.generator.ExternalBijections;
import cz.muni.fi.xklinec.whiteboxAES.generator.Generator;

/**
 * Standard Java Crypto API for White-box AES.
 * 
 * @author BacinskaL
 */
public final class AES_Cipher extends CipherSpi {

	private Generator generator = null;
	private boolean isEncrypting = true;
	private ExternalBijections extb = null;
	private AES coreAES = null;
	private byte[] dataBuffer = null;
	private int dataBufferActiveLength = 0;
	private State state = null;
	private int paddingScheme = 0; //0=NoPadding, 1=ISO9797m1, 2=ISO9797, 5=PKCS5
	
	/**
     * Creates an instance of WBAES with ECB mode.
     */
    public AES_Cipher() {
        generator = new Generator();
        dataBuffer = new byte[State.BYTES];
    }
    
    /*
     * Adds padding to the block of data
     */
	private void addPadding(byte[] data, int dataOffset, int dataLength) {
		int blockSize = engineGetBlockSize();
		
		if(paddingScheme == 2) {
			data[dataOffset] = (byte) 0x80;
			dataOffset++;
			dataLength++;

			if(dataLength > blockSize)
				dataLength = dataLength - blockSize;
		}
		
		if(paddingScheme == 1 || paddingScheme == 2) {
			while(dataLength < blockSize) {
				data[dataOffset] = (byte) 0x00;
				dataOffset++;
				dataLength++;
			}
		}
		
		if(dataLength == blockSize) dataLength = 0;
		
		if(paddingScheme == 5) {
			byte missingBytesNum = (byte)(blockSize - dataLength);
			for(int iter = dataOffset; iter<data.length; iter++) {
				data[iter] = missingBytesNum;
			}
		}
	}
	
	/*
	 * Counts length of padding to be able to remove it
	 */
	private int paddingCount(byte[] data) throws BadPaddingException {
	
	    int count = data.length - 1;

	    if(paddingScheme == 1 || paddingScheme == 2)
		    while (count > 0 && data[count] == 0) count--;
	
		if (data[count] != (byte)0x80 && paddingScheme == 2)
			throw new BadPaddingException("Wrong padding - block corrupted");
		
		if(paddingScheme == 1)
			count++;

	    if(paddingScheme == 5)
	    	return data[count];
	    
	    return data.length - count;
	}
	
	
    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part
     * operation.
     * The data is encrypted or decrypted, depending on how this cipher was initialized.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code> buffer,
     * starting at <code>inputOffset</code>, and any input bytes that may have been
     * buffered during a previous <code>update</code> operation, are processed,
     * with padding (if requested) being applied.
     * The result is stored in a new buffer.
     *
     * <p>The cipher is reset to its initial state (uninitialized) after this call.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     *
     * @return the new buffer with the result
     *
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {

		int length = 0;
		byte[] out = new byte[engineGetOutputSize(inputLen)];
		try {
			length = engineDoFinal(input, inputOffset, inputLen, out, 0);
		} catch(ShortBufferException e) { e.printStackTrace(); }

		if(length != out.length) {
			byte[] output = new byte[length];
			System.arraycopy(out, 0, output, 0, length);
			out = output;
		}
		return out;
	}

	/**
     * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part
     * operation.
     * The data is encrypted or decrypted, depending on how this cipher was initialized.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code> buffer,
     * starting at <code>inputOffset</code>, and any input bytes that may have been
     * buffered during a previous <code>update</code> operation, are processed,
     * with padding (if requested) being applied.
     * The result is stored in the <code>output</code> buffer, starting at <code>outputOffset</code>.
     *
     * <p>The cipher is reset to its initial state (uninitialized) after this call.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result is stored
     *
     * @return the number of bytes stored in <code>output</code>
     *
     * @exception IllegalBlockSizeException if this cipher is a block cipher,
     * no padding has been requested (only in encryption mode), and the total
     * input length of the data processed by this cipher is not a multiple of
     * block size
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     * @exception BadPaddingException if this cipher is in decryption mode,
     * and (un)padding has been requested, but the decrypted data is not
     * bounded by the appropriate padding bytes
     */
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

		int blockSize = engineGetBlockSize();
		int length = dataBufferActiveLength + inputLen;
				
		// check for "nothing to be done"
		if(length == 0)
			return 0;
			
		if(length % blockSize != 0 && paddingScheme == 0)
			throw new BadPaddingException("No padding used, input length n*blockSize expected");
			
		int outputSize = engineGetOutputSize(inputLen);
		
		// output size checking
		if ((output == null) || ((output.length - outputOffset) < outputSize)) {
			throw new ShortBufferException("Short output buffer - " + length + " bytes needed");
		}
				
		byte[] dataBufferWithInput = new byte[outputSize];
		System.arraycopy(dataBuffer, 0, dataBufferWithInput, 0, dataBufferActiveLength);
		System.arraycopy(input, inputOffset, dataBufferWithInput, dataBufferActiveLength, inputLen);
		
		int lastBlockSize = length % blockSize;
		if(lastBlockSize == 0 && length > 0 && paddingScheme != 0)
			lastBlockSize = blockSize;

		if(isEncrypting && paddingScheme != 0) {
			addPadding(dataBufferWithInput, length, lastBlockSize);
		}

		int outputLength = 0;
		for(int i = 0; i < outputSize; i += blockSize) {
			byte[] processingBlock = new byte[blockSize];
			System.arraycopy(dataBufferWithInput, i, processingBlock, 0, blockSize);
					
			state = new State(processingBlock, true,  false);
			state.transpose();
		    generator.applyExternalEnc(state, extb, true);
		    coreAES.crypt(state);
		    generator.applyExternalEnc(state, extb, false);
		            
		    System.arraycopy(state.getState(), 0, output, outputOffset + outputLength, blockSize);
			outputLength += blockSize;
		}
		
		if(!isEncrypting && paddingScheme != 0) {
			int paddingLength = paddingCount(output);
			return outputLength - paddingLength;
		}
		
		return outputLength;
	}
	
    /**
     * Returns the block size (in bytes).
     *
     * @return the block size (in bytes), or 0 if the underlying algorithm is not a block cipher
     */
	protected int engineGetBlockSize() {
		return State.BYTES;
	}
	
    /**
     * Returns the initialization vector (IV) in a new buffer.
     *
     * <p>This is useful in the case where a random IV has been created
     * (see <a href = "#init">init</a>),
     * or in the context of password-based encryption or
     * decryption, where the IV is derived from a user-provided password.
     *
     * @return the initialization vector in a new buffer, or null if the underlying
     * algorithm does not use an IV, or if the IV has not yet been set.
     */
	protected byte[] engineGetIV() {
		return null; 	//current implementation doesn't support modes using IV 
	}

    /**
     * Returns the length in bytes that an output buffer would need to be in order
     * to hold the result of the next <code>update</code> or <code>doFinal</code>
     * operation, given the input length <code>inputLen</code> (in bytes).
     *
     * <p>This call takes into account any unprocessed (buffered) data from a
     * previous <code>update</code> call, and padding.
     *
     * <p>The actual output length of the next <code>update</code> or <code>doFinal</code>
     * call may be smaller than the length returned by this method.
     *
     * @param inputLen the input length (in bytes)
     *
     * @return the required output buffer size (in bytes)
     */
	protected int engineGetOutputSize(int inputLen) {
		int size = dataBufferActiveLength + inputLen;

		int blockSize = engineGetBlockSize();
		int blocksNumber = (size + blockSize - 1) / blockSize;
		if(isEncrypting && (size % blockSize == 0) && (paddingScheme == 2 || paddingScheme == 5)) blocksNumber++;
		// when decrypting - return sumLen, when encrypting only without padding
		return blocksNumber * blockSize;
	}

    /**
     * Returns the parameters used with this cipher.
     *
     * <p>The returned parameters may be the same that were used to initialize
     * this cipher, or may contain the default set of parameters or a set of
     * randomly generated parameters used by the underlying cipher
     * implementation (provided that the underlying cipher implementation
     * uses a default set of parameters or creates new parameters if it needs
     * parameters but was not initialized with any).
     *
     * @return the parameters used with this cipher, or null if this cipher
     * does not use any parameters.
     */
	protected AlgorithmParameters engineGetParameters() {
		return null; //the only parameter for EAS would be IV, but not in this implementation (ECB mode)
	}
	
	/*
	 * converts Key to byte array
	 */
    private byte[] getKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("No key data");
        }
        if (!(key.getFormat()).equals("RAW")) {
            throw new InvalidKeyException("Wrong format: RAW needed");
        }
        byte[] keyBytes = key.getEncoded();
        if (keyBytes == null) {
            throw new InvalidKeyException("RAW key bytes missing");
        }
        return keyBytes;
    }
	

    /**
     * Initializes this cipher with a key and a source of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher requires an initialization vector (IV), it will get
     * it from <code>random</code>.
     * This behaviour should only be used in encryption or key wrapping
     * mode, however.
     * When initializing a cipher that requires an IV for decryption or
     * key unwrapping, the IV
     * (same IV that was used for encryption or key wrapping) must be provided
     * explicitly as a
     * parameter, in order to get the correct result.
     *
     * <p>This method also cleans existing buffer and other related state
     * information.
     *
     * @param opmode the operation mode of this cipher (this is one of
     * the following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the secret key
     * @param random the source of randomness
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     */
    protected void engineInit(int opmode, Key key, SecureRandom random)
			throws InvalidKeyException {
        try {
    		this.engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
	    } catch (InvalidAlgorithmParameterException e) {
	        throw new InvalidKeyException(e.getMessage());
	    }
	}

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes, it will get them from <code>random</code>.
     *
     * @param opmode the operation mode of this cipher (this is one of
     * the following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this cipher
     */
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		
		if(params != null)
			throw new InvalidAlgorithmParameterException("Current impelmentation doesn't support AlgorithmParameter");

        isEncrypting = (opmode == Cipher.ENCRYPT_MODE);
		
		if(key == null) {
			
			try {
		        FileInputStream fileIn = new FileInputStream("extb_tables_" + isEncrypting + ".ser");
		        ObjectInputStream in = new ObjectInputStream(fileIn);
		        extb = (ExternalBijections) in.readObject();
		        coreAES = (AES) in.readObject();
		        in.close();
		        fileIn.close();
		        System.out.println("Serialized data read successfully");
			} catch(IOException i) {
		        //i.printStackTrace();
				throw new InvalidKeyException(i.getMessage());
		    } catch(ClassNotFoundException c) {
		        System.out.println("ExternalBijections class (bijections) not found");
		        c.printStackTrace();
		        return;
		    }
			
		}
		else {
		
	    	byte[] keyBytes = getKey(key);
	    	
	    	if(random != null)
	    		generator.setRand(random);
	    		
	    	extb = new ExternalBijections();
	        generator.generateExtEncoding(extb, 0);
	        
	        // all protections are enabled (transformations are not identities)
	        generator.setUseIO04x04Identity(false);
	        generator.setUseIO08x08Identity(false);
	        generator.setUseMB08x08Identity(false);
	        generator.setUseMB32x32Identity(false);
	        
	        try {
	        	generator.generate(isEncrypting, keyBytes, keyBytes.length, extb);
	        } catch (ArrayIndexOutOfBoundsException e) {throw new InvalidKeyException("Wrong key length");}
	        coreAES = generator.getAESi();
	        
	        try {
	        	FileOutputStream fileOut = new FileOutputStream("extb_tables_" + isEncrypting + ".ser");
	            ObjectOutputStream out = new ObjectOutputStream(fileOut);
	            out.writeObject(extb);
	            out.writeObject(coreAES);
	            out.flush();
	            out.close();
	            fileOut.close();
	            System.out.println("Serialized data is saved in extb_tables_" + isEncrypting + ".ser");
	        } catch(IOException i) {
	            i.printStackTrace();
	        }
	        
		}
	}

    /**
     * Initializes this cipher with a key, a set of
     * algorithm parameters, and a source of randomness.
     *
     * <p>The cipher is initialized for one of the following four operations:
     * encryption, decryption, key wrapping or key unwrapping, depending on
     * the value of <code>opmode</code>.
     *
     * <p>If this cipher (including its underlying feedback or padding scheme)
     * requires any random bytes, it will get them from <code>random</code>.
     *
     * @param opmode the operation mode of this cipher (this is one of
     * the following:
     * <code>ENCRYPT_MODE</code>, <code>DECRYPT_MODE</code>,
     * <code>WRAP_MODE</code> or <code>UNWRAP_MODE</code>)
     * @param key the encryption key
     * @param params the algorithm parameters
     * @param random the source of randomness
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     * @exception InvalidAlgorithmParameterException if the given algorithm
     * parameters are inappropriate for this cipher
     */
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		if(params != null)
			throw new InvalidAlgorithmParameterException("Current impelmentation doesn't support AlgorithmParameter");

		this.engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
	}

    /**
     * Sets the mode of this cipher.
     *
     * @param mode the cipher mode
     *
     * @exception NoSuchAlgorithmException if the requested cipher mode does not exist
     */
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		if(mode == null)
			throw new NoSuchAlgorithmException("Mode is null");   
		if(!mode.equals("ECB"))
			throw new NoSuchAlgorithmException("Only ECB mode is supported");
	}

    /**
     * Sets the padding mechanism of this cipher.
     *
     * @param padding the padding mechanism
     *
     * @exception NoSuchPaddingException if the requested padding mechanism does not exist
     */
	// state sa pri vytvarani orezava/predlzuje (ak je copy true) na 16*8 bits
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		if(padding == null)
			throw new NoSuchPaddingException("Padding is null");
		else if(padding.equalsIgnoreCase("NoPadding")) paddingScheme = 0;
		else if(padding.equalsIgnoreCase("ISO9797M1Padding")) paddingScheme = 1;
		else if(padding.equalsIgnoreCase("ISO9797M2Padding")) paddingScheme = 2;
		else if(padding.equalsIgnoreCase("PKCS5Padding")) paddingScheme = 5;
		else throw new NoSuchPaddingException(padding + " is not supported");
	}

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code>, are processed, and the
     * result is stored in a new buffer.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     *
     * @return the new buffer with the result
     *
     * @exception IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized)
     */
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		int length = 0;
		byte[] out = new byte[engineGetOutputSize(inputLen)];
		try {
			length = engineUpdate(input, inputOffset, inputLen, out, 0);
		} catch(ShortBufferException e) { e.printStackTrace(); }

		if(length != out.length) {
			byte[] output = new byte[length];
			System.arraycopy(out, 0, output, 0, length);
			out = output;
		}
		return out;
	}

    /**
     * Continues a multiple-part encryption or decryption operation (depending
     * on how this cipher was initialized), processing another data part.
     *
     * <p>The first <code>inputLen</code> bytes in the <code>input</code>
     * buffer, starting at <code>inputOffset</code>, are processed, and the
     * result is stored in the <code>output</code> buffer, starting at
     * <code>outputOffset</code>.
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result is stored
     *
     * @return the number of bytes stored in <code>output</code>
     *
     * @exception ShortBufferException if the given output buffer is too small
     * to hold the result
     */
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {
					
		int length = dataBufferActiveLength + inputLen;
		
		// check for "nothing to be done"
		if(length == 0)
			return 0;
		
		// output size checking
		int blockSize = engineGetBlockSize();
		int processingDataLength = length  - (length % blockSize);
		if ((output == null) || ((output.length - outputOffset) < processingDataLength)) {
	        throw new ShortBufferException("Short output buffer - " + processingDataLength + " bytes needed");
	    }
		
		byte[] dataBufferWithInput = new byte[length];
		System.arraycopy(dataBuffer, 0, dataBufferWithInput, 0, dataBufferActiveLength);
		System.arraycopy(input, inputOffset, dataBufferWithInput, dataBufferActiveLength, inputLen);
		
		int outputLength = 0;
		for(int i = 0; i < processingDataLength; i += blockSize) {
			byte[] processingBlock = new byte[blockSize];
			System.arraycopy(dataBufferWithInput, i, processingBlock, 0, blockSize);
			
			state  = new State(processingBlock, true,  false);
			state.transpose();
            generator.applyExternalEnc(state, extb, true); // canceling the effect of external encodings in the first round
            coreAES.crypt(state);
            generator.applyExternalEnc(state, extb, false); // canceling the effect of external encodings in the last round
            
            System.arraycopy(state.getState(), 0, output, outputOffset + outputLength, blockSize);
			outputLength += blockSize;
		}
		
		dataBufferActiveLength = length % blockSize;
		System.arraycopy(dataBufferWithInput, processingDataLength, dataBuffer, 0, dataBufferActiveLength);
		
		return outputLength;
	}
	
    /**
     *  Returns the key size of the given key object.
     *
     * @param key the key object.
     *
     * @return the key size of the given key object.
     *
     * @exception InvalidKeyException if <code>key</code> is invalid.
     */
	// use only in secure environment
	protected int engineGetKeySize(Key key) throws InvalidKeyException{
		return getKey(key).length;
	}

}
