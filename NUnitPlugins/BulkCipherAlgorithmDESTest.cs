//
// BulkCipherAlgorithmDESTest
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

using NUnit.Framework;
using System;
using System.Security.Cryptography;
using AaltoTLS.PluginInterface;

namespace BaseCipherSuitePlugin
{
	[TestFixture]
	public class BulkCipherAlgorithmDESTest
	{
		BulkCipherAlgorithmDES cipher = new BulkCipherAlgorithmDES();
		
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void EncryptionKeyNull ()
		{
			cipher.CreateEncryptor(null, null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void EncryptionKeyInvalid ()
		{
			cipher.CreateEncryptor(new byte[7], null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void EncryptionKeyWeak ()
		{
			cipher.CreateEncryptor(new byte[8], new byte[8]);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void EncryptionIVInvalid ()
		{
			cipher.CreateEncryptor(new byte[8], new byte[7]);
		}
		
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void DecryptionKeyNull ()
		{
			cipher.CreateDecryptor(null, null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void DecryptionKeyInvalid ()
		{
			cipher.CreateDecryptor(new byte[7], null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void DecryptionKeyWeak ()
		{
			cipher.CreateDecryptor(new byte[8], new byte[8]);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void DecryptionIVInvalid ()
		{
			cipher.CreateDecryptor(new byte[8], new byte[7]);
		}
		
		[Test]
		public void Constructor ()
		{
			byte[] key = new byte[] {
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
			};
			
			Assert.AreEqual (8, cipher.KeySize);
			Assert.AreEqual (8, cipher.BlockSize);
			Assert.AreEqual (56, cipher.Strength);
			Assert.AreEqual (BulkCipherAlgorithmType.Block, cipher.Type);
			Assert.IsTrue (cipher.SupportsProtocolVersion(ProtocolVersion.TLS1_0));
			Assert.IsTrue (cipher.SupportsProtocolVersion(ProtocolVersion.DTLS1_0));
			Assert.IsNotNull (cipher.CreateEncryptor(key, null));
			Assert.IsNotNull (cipher.CreateDecryptor(key, null));
			Assert.IsNotNull (cipher.CreateEncryptor(key, new byte[8]));
			Assert.IsNotNull (cipher.CreateDecryptor(key, new byte[8]));
		}
	}
}

