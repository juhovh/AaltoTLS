//
// AaltoTLS.PluginInterface.GenericCbcModeCryptoTransform
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
	public class GenericCbcModeCryptoTransform : ICryptoTransform
	{
		private bool _disposed = false;
		
		private IGenericBlockCipher _cipher;
		private int _blockSize;
		private bool _encrypting;
		
		private byte[] _originalIV;
		private byte[] _currentIV;
		
		public bool CanReuseTransform { get { return true; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return _blockSize; } }
		public int OutputBlockSize { get { return _blockSize; } }
	
		public GenericCbcModeCryptoTransform(IGenericBlockCipher cipher, bool forEncryption, byte[] iv)
		{
			if (cipher == null)
				throw new ArgumentNullException("cipher");
			if (iv == null)
				throw new ArgumentNullException("iv");
			if (iv.Length != cipher.BlockSize)
				throw new ArgumentException("IV length " + iv.Length + ", expected " + cipher.BlockSize);
			
			_cipher = cipher;
			_blockSize = cipher.BlockSize;
			_encrypting = forEncryption;
			
			_originalIV = (byte[])iv.Clone();
			_currentIV = new byte[_blockSize];
			
			Reset();
		}
		
		private void Reset()
		{
			Buffer.BlockCopy(_originalIV, 0, _currentIV, 0, _blockSize);
		}

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
			if (inputOffset < 0 || inputOffset >= inputBuffer.Length)
				throw new ArgumentOutOfRangeException("inputOffset");
			if (inputCount < 0 || inputCount > inputBuffer.Length-inputOffset)
				throw new ArgumentOutOfRangeException("inputCount");
			if (inputCount % _blockSize != 0)
				throw new CryptographicException("inputCount");
			if (outputBuffer == null)
				throw new ArgumentNullException("outputBuffer");
			if (outputOffset < 0 || outputOffset > outputBuffer.Length-inputCount)
				throw new ArgumentOutOfRangeException("outputOffset");
			
			// This is manual CBC handling
			for (int i=0; i<inputCount; i+=_blockSize) {
				if (_encrypting) {
					for (int j=0; j<_blockSize; j++) {
						_currentIV[j] ^= inputBuffer[inputOffset+i+j];
					}
					_cipher.Encrypt(_currentIV, 0, outputBuffer, outputOffset+i);
					Array.Copy(outputBuffer, outputOffset+i, _currentIV, 0, _blockSize);
				} else {
					_cipher.Decrypt(inputBuffer, inputOffset+i, outputBuffer, outputOffset+i);
					for (int j=0; j<_blockSize; j++) {	
						outputBuffer[outputOffset+i+j] ^= _currentIV[j];
					}
					Array.Copy(inputBuffer, inputOffset+i, _currentIV, 0, _blockSize);
				}
			}

			return inputCount;
		}
		
		// Should return null in case of error
		public byte[] TransformFinalBlock(byte[] inputBuffer,
		                                  int inputOffset,
		                                  int inputCount)
		{
			if (_disposed) {
				throw new ObjectDisposedException(GetType().FullName);
			}
			
			if (inputBuffer == null)
				throw new ArgumentNullException("inputBuffer");
			if (inputOffset < 0 || inputOffset >= inputBuffer.Length)
				throw new ArgumentOutOfRangeException("inputOffset");
			if (inputCount < 0 || inputCount > inputBuffer.Length-inputOffset)
				throw new ArgumentOutOfRangeException("inputCount");
			if (inputCount % _blockSize != 0)
				throw new CryptographicException("inputCount");
			
			byte[] outputBuffer = new byte[inputCount];
			TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, 0);
			
			Reset();
			return outputBuffer;
		}

		public void Dispose()
		{
			_disposed = true;
		}
	}
}

