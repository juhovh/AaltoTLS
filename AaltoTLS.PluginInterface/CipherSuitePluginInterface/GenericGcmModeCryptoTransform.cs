//
// AaltoTLS.PluginInterface.GenericGcmModeCryptoTransform
//
// Authors:
//      Juho Vähä-Herttua  <juhovh@iki.fi>
//
// Copyright (C) 2010-2011  Aalto University
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

using System;
using System.Security.Cryptography;

namespace AaltoTLS.PluginInterface
{
	public class GenericGcmModeCryptoTransform : ICryptoTransform
	{
		private const int BLOCK_SIZE = 16;
		private bool _disposed = false;
		
		private IGenericBlockCipher _cipher;
		private bool _encrypting;
		private int _tagLength;
		
		private byte[] _H = new byte[BLOCK_SIZE];
		private byte[] _J0 = new byte[BLOCK_SIZE];
		
		private byte[] _originalS = new byte[BLOCK_SIZE];
		private byte[] _currentS = new byte[BLOCK_SIZE];
		private byte[] _counter = new byte[BLOCK_SIZE];
		
		private UInt64 _additionalLength;
		private UInt64 _ciphertextLength;
		
		public bool CanReuseTransform { get { return true; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return BLOCK_SIZE; } }
		public int OutputBlockSize { get { return BLOCK_SIZE; } }
		
		public GenericGcmModeCryptoTransform(IGenericBlockCipher cipher, bool forEncryption,
		                                     byte[] iv, byte[] additional, int tagLength)
		{
			if (cipher == null)
				throw new ArgumentNullException("cipher");
			if (cipher.BlockSize != BLOCK_SIZE)
				throw new ArgumentException("cipher");
			if (iv == null)
				throw new ArgumentNullException("iv");
			if (additional == null)
				throw new ArgumentNullException("additional");
			if (tagLength < 12 || tagLength > 16)
				throw new ArgumentException("tagLength " + tagLength);
			
			_cipher = cipher;
			_encrypting = forEncryption;
			_tagLength = tagLength;
			_cipher.Encrypt(_H, 0, _H, 0);
			
			if (iv.Length == 12) {
				Buffer.BlockCopy(iv, 0, _J0, 0, 12);
				_J0[_J0.Length-1] = 0x01;
			} else {
				// Construct last hashed block from IV length
				byte[] lengthBytes = BitConverter.GetBytes((UInt64)iv.Length*8);
				if (BitConverter.IsLittleEndian) {
					Array.Reverse(lengthBytes);
				}
				byte[] lastBlock = new byte[BLOCK_SIZE];
				Buffer.BlockCopy(lengthBytes, 0, lastBlock, 8, 8);
				
				// Hash the IV and length block to get J0
				GHASH(iv, _J0);
				GHASH(_J0, lastBlock, 0, lastBlock.Length, _J0);
			}
			
			GHASH(additional, _originalS);
			_additionalLength = (UInt64)additional.Length;
			
			Reset();
		}
		
		private void Reset()
		{
			Buffer.BlockCopy(_originalS, 0, _currentS, 0, BLOCK_SIZE);
			Buffer.BlockCopy(_J0, 0, _counter, 0, BLOCK_SIZE);
			Increment(32, _counter);
			
			_ciphertextLength = 0;
		}
		
		// Takes only full data blocks for input, especially need to make sure that
		// the authentication tag is not given to TransformBlock while decrypting GCM
		// data, it needs to be handled in TransformFinalBlock instead
		public int TransformBlock(byte[] inputBuffer,
		                          int inputOffset,
		                          int inputCount,
		                          byte[] outputBuffer,
		                          int outputOffset)
		{
			if (_disposed) {
				throw new ObjectDisposedException(GetType().FullName);
			}
			
			if (inputBuffer == null)
				throw new ArgumentNullException("inputBuffer");
			if (inputOffset < 0 || inputOffset > inputBuffer.Length)
				throw new ArgumentOutOfRangeException("inputOffset");
			if (inputCount < 0 || inputCount > inputBuffer.Length-inputOffset)
				throw new ArgumentOutOfRangeException("inputCount");
			if (inputCount % BLOCK_SIZE != 0)
				throw new CryptographicException("inputCount");
			if (outputBuffer == null)
				throw new ArgumentNullException("outputBuffer");
			if (outputOffset < 0 || outputOffset > outputBuffer.Length-inputCount)
				throw new ArgumentOutOfRangeException("outputOffset");
			
			for (int i=0; i<inputCount; i+=BLOCK_SIZE) {
				// Encrypt the next counter to the output buffer
				_cipher.Encrypt(_counter, 0, outputBuffer, outputOffset+i);
				Increment(32, _counter);
				
				// XOR input with the counter and place it in output
				for (int j=0; j<BLOCK_SIZE; j++) {
					outputBuffer[outputOffset+i+j] ^= inputBuffer[inputOffset+i+j];
				}
				
				if (_encrypting) {
					GHASH(_currentS, outputBuffer, outputOffset+i, BLOCK_SIZE, _currentS);
				} else {
					GHASH(_currentS, inputBuffer, inputOffset+i, BLOCK_SIZE, _currentS);
				}
				_ciphertextLength += BLOCK_SIZE;
			}
			
			return inputCount;
		}
		
		// Takes any number of data bytes concatenated with the authentication tag
		// Should return null in case of error, zero buffer in case of tag only input
		public byte[] TransformFinalBlock(byte[] inputBuffer,
		                                  int inputOffset,
		                                  int inputCount)
		{
			if (_disposed) {
				throw new ObjectDisposedException(GetType().FullName);
			}
			
			if (inputBuffer == null)
				throw new ArgumentNullException("inputBuffer");
			if (inputOffset < 0 || inputOffset > inputBuffer.Length)
				throw new ArgumentOutOfRangeException("inputOffset");
			if (inputCount < 0)
				throw new ArgumentOutOfRangeException("inputCount");
			if (!_encrypting && inputCount < _tagLength)
				throw new CryptographicException("inputCount");
			
			byte[] outputBuffer;
			int datalen;
			if (_encrypting) {
				outputBuffer = new byte[inputCount + _tagLength];
				datalen = inputCount;
			} else {
				outputBuffer = new byte[inputCount - _tagLength];
				datalen = inputCount - _tagLength;
			}
			
			for (int i=0; i<datalen; i+=BLOCK_SIZE) {
				// Encrypt the next counter to the counter block
				byte[] counterBlock = new byte[BLOCK_SIZE];
				_cipher.Encrypt(_counter, 0, counterBlock, 0);
				Increment(32, _counter);
				
				int bytesleft = System.Math.Min(BLOCK_SIZE, datalen-i);
				for (int j=0; j<bytesleft; j++) {
					outputBuffer[i+j] = (byte)(inputBuffer[inputOffset+i+j] ^ counterBlock[j]);
				}
				if (_encrypting) {
					GHASH(_currentS, outputBuffer, i, bytesleft, _currentS);
				} else {
					GHASH(_currentS, inputBuffer, inputOffset+i, bytesleft, _currentS);
				}
				_ciphertextLength += (UInt64)bytesleft;
			}
			
			// Get additional and ciphertext lengths as byte arrays
			byte[] adLengthBytes = BitConverter.GetBytes((UInt64)_additionalLength*8);
			byte[] cLengthBytes = BitConverter.GetBytes((UInt64)_ciphertextLength*8);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(adLengthBytes);
				Array.Reverse(cLengthBytes);
			}
			
			// Construct last block from additional and ciphertext lengths
			byte[] lastBlock = new byte[BLOCK_SIZE];
			Buffer.BlockCopy(adLengthBytes, 0, lastBlock, 0, 8);
			Buffer.BlockCopy(cLengthBytes, 0, lastBlock, 8, 8);
			
			// Update the GHASH with length block
			GHASH(_currentS, lastBlock, 0, lastBlock.Length, _currentS);
			
			// Calculate counter for authentication tag
			byte[] tagBlock = new byte[BLOCK_SIZE];
			_cipher.Encrypt(_J0, 0, tagBlock, 0);
			for (int i=0; i<_tagLength; i++) {
				tagBlock[i] ^= _currentS[i];
			}
			
			if (_encrypting) {
				Buffer.BlockCopy(tagBlock, 0, outputBuffer, inputCount, _tagLength);
			} else {
				bool validated = true;
				for (int i=0; i<_tagLength; i++) {
					if (inputBuffer[inputOffset+datalen+i] != tagBlock[i]) {
						validated = false;
					}
				}
				if (!validated)
					return null;
			}
			
			Reset();
			return outputBuffer;
		}

		public void Dispose()
		{
			_disposed = true;
		}
		
		
		
		
		
		private static void Increment(int s, byte[] block)
		{
			if (s%8 != 0 || s/8 > block.Length)
				throw new ArgumentOutOfRangeException("s");
			if (block.Length != BLOCK_SIZE)
				throw new ArgumentException("block");
			
			for (int i=block.Length-1; i>=block.Length-s/8; i--) {
				block[i] += 1;
				if (block[i] != 0)
					break;
			}
		}
		
		private static byte[] GaloisMultiply(byte[] x, byte[] y)
		{
			if (x.Length != BLOCK_SIZE)
				throw new ArgumentException("x");
			if (y.Length != BLOCK_SIZE)
				throw new ArgumentException("y");
			
			byte[] Zi = new byte[BLOCK_SIZE];
			byte[] Vi = (byte[])y.Clone();
			
			// Run the multiply loop for 128 times (we return Z_128)
			for (int i=0; i<BLOCK_SIZE*8; i++) {
				// Calculate the x_i value
				bool xi = (x[i/8] & (1 << (7-i%8))) != 0;
				if (xi) {
					// Z_i+1 = Z_i ^ V_i
					for (int j=0; j<BLOCK_SIZE; j++) {
						Zi[j] ^= Vi[j];
					}
				}
				
				// Store the value of LSB(V_i)
				bool lsb_Vi = (Vi[BLOCK_SIZE-1] & 1) != 0;
				
				// V_i+1 = V_i >> 1
				for (int j=BLOCK_SIZE-1; j>0; j--) {
					Vi[j] = (byte) ((Vi[j] >> 1) | (Vi[j-1] << 7));
				}
				Vi[0] >>= 1;
				
				// If LSB(V_i) is 1, V_i+1 = (V_i >> 1) ^ R
				if (lsb_Vi) {
					Vi[0] ^= 0xe1;
				}
			}
			return Zi;
		}
		
		private void GHASH(byte[] inputBuffer, byte[] outputBuffer)
		{
			GHASH(new byte[BLOCK_SIZE], inputBuffer, 0, inputBuffer.Length, outputBuffer);
		}
		
		private void GHASH(byte[] Y0, byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer)
		{
			if (Y0.Length != BLOCK_SIZE)
				throw new ArgumentException("Yi");
			if (inputBuffer == null)
				throw new ArgumentNullException("inputBuffer");
			if (inputOffset < 0 || inputOffset > inputBuffer.Length)
				throw new ArgumentOutOfRangeException("inputOffset");
			if (inputCount < 0 || inputCount > inputBuffer.Length-inputOffset)
				throw new ArgumentOutOfRangeException("inputCount");
			if (outputBuffer == null)
				throw new ArgumentNullException("outputBuffer");
			if (outputBuffer.Length != BLOCK_SIZE)
				throw new CryptographicException("outputBuffer");
			
			byte[] Yi = (byte[])Y0.Clone();
			for (int i=inputOffset; i<inputOffset+inputCount; i+=BLOCK_SIZE) {
				byte[] Xi = new byte[BLOCK_SIZE];
				int datalen = System.Math.Min(inputOffset+inputCount-i, BLOCK_SIZE);
				Buffer.BlockCopy(inputBuffer, i, Xi, 0, datalen);
				for (int j=0; j<BLOCK_SIZE; j++) {
					Yi[j] ^= Xi[j];
				}
				Yi = GaloisMultiply(Yi, _H);
			}
			Buffer.BlockCopy(Yi, 0, outputBuffer, 0, BLOCK_SIZE);
		}
	}
}

