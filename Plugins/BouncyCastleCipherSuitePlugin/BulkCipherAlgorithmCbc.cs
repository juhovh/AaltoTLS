//
// BulkCipherAlgorithmCbc
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
	public class BulkCipherAlgorithmCbc<BlockCipherType> : BulkCipherAlgorithm where BlockCipherType : IBlockCipher,new()
	{
		private int _keySize;
		private int _blockSize;
		
		public BulkCipherAlgorithmCbc(int keySize)
		{
			if (keySize%8 != 0)
				throw new ArgumentException("keySize");
			_keySize = keySize/8;
			
			// Make sure the key size is valid for this cipher and get block size
			BlockCipherType cipher = new BlockCipherType();
			cipher.Init(true, new KeyParameter(new byte[_keySize]));
			_blockSize = cipher.GetBlockSize();
		}

		public override int KeySize
		{
			get { return _keySize; }
		}

		public override int BlockSize
		{
			get { return _blockSize; }
		}
		
		public override int Strength
		{
			get { return _keySize*8; }
		}

		public override BulkCipherAlgorithmType Type
		{
			get { return BulkCipherAlgorithmType.Block; }
		}

		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}

		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			if (rgbKey == null)
				throw new ArgumentNullException("rgbKey");
			if (rgbKey.Length != _keySize)
				throw new CryptographicException("rgbKey");
			if (rgbIV == null)
				throw new ArgumentNullException("rgbIV");
			if (rgbIV.Length != BlockSize)
				throw new CryptographicException("rgbIV");
			
			BouncyCastleBlockCipher<BlockCipherType> cipher = new BouncyCastleBlockCipher<BlockCipherType>(rgbKey);
			return new GenericCbcModeCryptoTransform(cipher, true, rgbIV);
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			if (rgbKey == null)
				throw new ArgumentNullException("rgbKey");
			if (rgbKey.Length != _keySize)
				throw new CryptographicException("rgbKey");
			if (rgbIV == null)
				throw new ArgumentNullException("rgbIV");
			if (rgbIV.Length != BlockSize)
				throw new CryptographicException("rgbIV");
			
			BouncyCastleBlockCipher<BlockCipherType> cipher = new BouncyCastleBlockCipher<BlockCipherType>(rgbKey);
			return new GenericCbcModeCryptoTransform(cipher, false, rgbIV);
		}
	}
}

