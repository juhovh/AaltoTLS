//
// BulkCipherAlgorithmDES
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
	public class BulkCipherAlgorithmDES : BulkCipherAlgorithm
	{
		DESCryptoServiceProvider _csp;

		public BulkCipherAlgorithmDES()
		{
			_csp = new DESCryptoServiceProvider();
			_csp.Padding = PaddingMode.None;
			_csp.Mode = CipherMode.CBC;
			_csp.KeySize = 64;
			_csp.BlockSize = 64;
		}

		public override int KeySize
		{
			get { return 8; }
		}

		public override int BlockSize
		{
			get { return 8; }
		}

		public override int Strength
		{
			get { return 56; }
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
			
			return _csp.CreateEncryptor(rgbKey, rgbIV);
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			if (rgbKey == null)
				throw new ArgumentNullException("rgbKey");
			
			return _csp.CreateDecryptor(rgbKey, rgbIV);
		}
	}
}
