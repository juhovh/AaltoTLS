//
// BulkCipherAlgorithmAES
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
	public class BulkCipherAlgorithmAES : BulkCipherAlgorithm
	{
		private RijndaelManaged _csp;

		public BulkCipherAlgorithmAES(int keySize)
		{
			if (keySize != 128 && keySize != 192 && keySize != 256) {
				throw new CryptographicException("Invalid AES key size: " + keySize);
			}

			_csp = new RijndaelManaged();
			_csp.Padding = PaddingMode.None;
			_csp.Mode = CipherMode.CBC;
			_csp.KeySize = keySize;
			_csp.BlockSize = 128;
		}

		public override int KeySize
		{
			get { return _csp.KeySize/8; }
		}

		public override int BlockSize
		{
			get { return 16; }
		}
		
		public override int Strength
		{
			get { return _csp.KeySize; }
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
			if (rgbKey.Length != _csp.KeySize/8)
				throw new CryptographicException("rgbKey");
			
			return _csp.CreateEncryptor(rgbKey, rgbIV);
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			if (rgbKey == null)
				throw new ArgumentNullException("rgbKey");
			if (rgbKey.Length != _csp.KeySize/8)
				throw new CryptographicException("rgbKey");
			
			return _csp.CreateDecryptor(rgbKey, rgbIV);
		}
	}
}
