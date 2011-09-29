//
// BulkCipherAlgorithmARCFourTest
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

namespace ARCFourCipherSuitePlugin
{
	[TestFixture]
	public class BulkCipherAlgorithmARCFourTest
	{
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void ConstructorKeySizeInvalid ()
		{
			new BulkCipherAlgorithmARCFour(129);
		}
		
		[Test]
		[ExpectedException (typeof (ArgumentOutOfRangeException))]
		public void ConstructorKeySizeZero ()
		{
			new BulkCipherAlgorithmARCFour(0);
		}
		
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void EncryptionKeyNull ()
		{
			BulkCipherAlgorithmARCFour cipher = new BulkCipherAlgorithmARCFour(128);
			cipher.CreateEncryptor(null, null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void EncryptionKeyInvalid ()
		{
			BulkCipherAlgorithmARCFour cipher = new BulkCipherAlgorithmARCFour(128);
			cipher.CreateEncryptor(new byte[15], null);
		}
		
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void DecryptionKeyNull ()
		{
			BulkCipherAlgorithmARCFour cipher = new BulkCipherAlgorithmARCFour(128);
			cipher.CreateDecryptor(null, null);
		}
		
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void DecryptionKeyInvalid ()
		{
			BulkCipherAlgorithmARCFour cipher = new BulkCipherAlgorithmARCFour(128);
			cipher.CreateDecryptor(new byte[15], null);
		}
		
		private void Check (BulkCipherAlgorithmARCFour cipher, int keySize)
		{
			Assert.AreEqual (keySize/8, cipher.KeySize);
			Assert.AreEqual (0, cipher.BlockSize);
			Assert.AreEqual (keySize, cipher.Strength);
			Assert.AreEqual (BulkCipherAlgorithmType.Stream, cipher.Type);
			Assert.IsTrue (cipher.SupportsProtocolVersion(ProtocolVersion.TLS1_0));
			Assert.IsFalse (cipher.SupportsProtocolVersion(ProtocolVersion.DTLS1_0));
			Assert.IsNotNull (cipher.CreateEncryptor(new byte[keySize/8], null));
			Assert.IsNotNull (cipher.CreateDecryptor(new byte[keySize/8], null));
		}
		
		[Test]
		public void Constructor ()
		{
			Check (new BulkCipherAlgorithmARCFour(128), 128);
			Check (new BulkCipherAlgorithmARCFour(256), 256);
		}
	}
}

