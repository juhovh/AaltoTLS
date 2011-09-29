//
// BouncyCastleBlockCipher
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
using AaltoTLS.PluginInterface;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace BouncyCastleCipherSuitePlugin
{
	public class BouncyCastleBlockCipher<BlockCipherType> : IGenericBlockCipher where BlockCipherType : IBlockCipher,new()
	{
		private int _blockSize;
		private IBlockCipher _encryptor;
		private IBlockCipher _decryptor;
		
		public int BlockSize
		{
			get { return _blockSize; }
		}
		
		public BouncyCastleBlockCipher(byte[] key)
		{
			_blockSize = new BlockCipherType().GetBlockSize();
			
			ICipherParameters param = new KeyParameter(key);
			
			_encryptor = new BlockCipherType();
			_encryptor.Init(true, param);
			
			_decryptor = new BlockCipherType();
			_decryptor.Init(false, param);
		}
		
		public void Encrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			_encryptor.ProcessBlock(inputBuffer, inputOffset, outputBuffer, outputOffset);
		}
		
		public void Decrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			_decryptor.ProcessBlock(inputBuffer, inputOffset, outputBuffer, outputOffset);
		}
	}
}

