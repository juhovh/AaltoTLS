//
// AaltoTLS.PluginInterface.BulkCipherAlgorithm
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
	public abstract class BulkCipherAlgorithm
	{
		// KeySize and BlockSize in bytes, Strenght in bits
		public abstract int KeySize { get; }
		public abstract int BlockSize { get; }
		public abstract int Strength { get; }
		public abstract BulkCipherAlgorithmType Type { get; }

		// These should be overridden by AEAD ciphers
		public virtual int AuthenticationTagSize { get { return 0; } }
		public virtual int FixedIVLength { get { return BlockSize; } }
		public virtual int RecordIVLength { get { return BlockSize; } }

		// Returns true if this version is supported, otherwise false
		public abstract bool SupportsProtocolVersion(ProtocolVersion version);
		
		// The additional bytes should only be used by AEAD ciphers, rgbIV not used with stream ciphers
		public abstract ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional);
		public abstract ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional);

		// Helper functions when additional bytes are not necessary
		public ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
		{
			return CreateEncryptor(rgbKey, rgbIV, new byte[0]);
		}

		public ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
		{
			return CreateDecryptor(rgbKey, rgbIV, new byte[0]);
		}

	}
}
