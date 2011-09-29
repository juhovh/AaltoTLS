//
// AesBlockCipher
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

namespace BaseCipherSuitePlugin
{
	public class AesBlockCipher : IGenericBlockCipher
	{
		private const int BLOCK_SIZE = 16;
		
		private ICryptoTransform _encryptor;
		private ICryptoTransform _decryptor;
		
		public int BlockSize
		{
			get { return BLOCK_SIZE; }
		}
		
		public AesBlockCipher(byte[] key)
		{
			RijndaelManaged csp = new RijndaelManaged();
			csp.Padding = PaddingMode.None;
			csp.Mode = CipherMode.ECB;
			csp.KeySize = key.Length*8;
			csp.BlockSize = BLOCK_SIZE*8;
			
			_encryptor = csp.CreateEncryptor(key, new byte[BLOCK_SIZE]);
			_decryptor = csp.CreateDecryptor(key, new byte[BLOCK_SIZE]);
		}
		
		public void Encrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			_encryptor.TransformBlock(inputBuffer, inputOffset, BLOCK_SIZE, outputBuffer, outputOffset);
		}
		
		public void Decrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
		{
			_decryptor.TransformBlock(inputBuffer, inputOffset, BLOCK_SIZE, outputBuffer, outputOffset);
		}
	}
}

