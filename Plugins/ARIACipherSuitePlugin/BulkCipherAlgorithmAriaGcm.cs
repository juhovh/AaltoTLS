//
// BulkCipherAlgorithmAriaGcm
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

namespace ARIACipherSuitePlugin
{
	public class BulkCipherAlgorithmAriaGcm : BulkCipherAlgorithm
	{
		private int _keySize;
		private int _tagSize;

		public BulkCipherAlgorithmAriaGcm(int keySize, int tagSize)
		{
			if (keySize != 128 && keySize != 192 && keySize != 256) {
				throw new CryptographicException("Invalid ARIA key size: " + keySize);
			}
			if (tagSize != 96 && tagSize != 104 && tagSize != 112 && tagSize != 120 && tagSize != 128) {
				throw new CryptographicException("Unsupported tag size: " + tagSize);
			}
			_keySize = keySize/8;
			_tagSize = tagSize/8;
		}

		public override int KeySize
		{
			get { return _keySize; }
		}

		public override int BlockSize
		{
			get { return 16; }
		}
		
		public override int Strength
		{
			get { return _keySize*8; }
		}

		public override BulkCipherAlgorithmType Type
		{
			get { return BulkCipherAlgorithmType.AEAD; }
		}

		public override int AuthenticationTagSize
		{
			get { return _tagSize; }
		}
		
		public override int FixedIVLength {
			get { return 4; }
		}
		
		public override int RecordIVLength {
			get { return 8; }
		}
		
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return version.HasAeadSupport;
		}

		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			if (rgbKey == null)
				throw new ArgumentNullException("rgbKey");
			if (rgbKey.Length != _keySize)
				throw new CryptographicException("rgbKey");
			if (rgbIV == null)
				throw new ArgumentNullException("rgbIV");
			if (additional == null)
				throw new ArgumentNullException("additional");
			
			IGenericBlockCipher cipher = new AriaBlockCipher(rgbKey);
			return new GenericGcmModeCryptoTransform(cipher, true, rgbIV, additional, _tagSize);
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			if (rgbKey == null)
				throw new ArgumentNullException("rgbKey");
			if (rgbKey.Length != _keySize)
				throw new CryptographicException("rgbKey");
			if (rgbIV == null)
				throw new ArgumentNullException("rgbIV");
			if (additional == null)
				throw new ArgumentNullException("additional");
			
			IGenericBlockCipher cipher = new AriaBlockCipher(rgbKey);
			return new GenericGcmModeCryptoTransform(cipher, false, rgbIV, additional, _tagSize);
		}
	}
}