//
// BulkCipherAlgorithmAESTest
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
	public class BulkCipherAlgorithmAESTest
	{
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void EncryptionKeyNull ()
		{
			BulkCipherAlgorithmAES cipher = new BulkCipherAlgorithmAES(128);
			cipher.CreateEncryptor(null, null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void EncryptionKeyInvalid ()
		{
			BulkCipherAlgorithmAES cipher = new BulkCipherAlgorithmAES(128);
			cipher.CreateEncryptor(new byte[15], null);
		}
		
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void DecryptionKeyNull ()
		{
			BulkCipherAlgorithmAES cipher = new BulkCipherAlgorithmAES(128);
			cipher.CreateDecryptor(null, null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void DecryptionKeyInvalid ()
		{
			BulkCipherAlgorithmAES cipher = new BulkCipherAlgorithmAES(128);
			cipher.CreateDecryptor(new byte[15], null);
		}
		
		private void Check (int keySize)
		{
			BulkCipherAlgorithmAES cipher = new BulkCipherAlgorithmAES(keySize);
			Assert.AreEqual (keySize/8, cipher.KeySize);
			Assert.AreEqual (16, cipher.BlockSize);
			Assert.AreEqual (keySize, cipher.Strength);
			Assert.AreEqual (BulkCipherAlgorithmType.Block, cipher.Type);
			Assert.IsTrue (cipher.SupportsProtocolVersion(ProtocolVersion.TLS1_0));
			Assert.IsTrue (cipher.SupportsProtocolVersion(ProtocolVersion.DTLS1_0));
			Assert.IsNotNull (cipher.CreateEncryptor(new byte[keySize/8], null));
			Assert.IsNotNull (cipher.CreateDecryptor(new byte[keySize/8], null));
			Assert.IsNotNull (cipher.CreateEncryptor(new byte[keySize/8], new byte[16]));
			Assert.IsNotNull (cipher.CreateDecryptor(new byte[keySize/8], new byte[16]));
		}
		
		[Test]
		public void Constructor ()
		{
			Check (128);
			Check (192);
			Check (256);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void InvalidKeySize ()
		{
			new BulkCipherAlgorithmAES(64);
		}
	}
}

