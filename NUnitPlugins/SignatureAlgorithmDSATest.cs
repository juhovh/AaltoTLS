//
// SignatureAlgorithmDSATest
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
	public class SignatureAlgorithmDSATest
	{
		[Test]
		public void Constructor ()
		{
			SignatureAlgorithmDSA dsa = new SignatureAlgorithmDSA();
			Assert.AreEqual ("1.2.840.10040.4.1", dsa.CertificateKeyAlgorithm);
			Assert.AreEqual (2, dsa.SignatureAlgorithmType);
			Assert.IsTrue (dsa.SupportsProtocolVersion(ProtocolVersion.TLS1_0));
			Assert.IsFalse (dsa.SupportsHashAlgorithmType(1));
			Assert.IsTrue (dsa.SupportsHashAlgorithmType(2));
		}
		
		[Test]
		public void VerifySignatureTest ()
		{
			string dsaKeys =
				"<DSAKeyValue>" +
				"<P>6akTyOvXOB5LjK2ui9iMyyuDAXKLE0K5mo9OC1AxuU4sz1bfPZ194ENPjqXki10+iUiVR9ZzOnQZA1Mmh91m5Q==</P>" +
				"<Q>zaJn38GM1L9hEiB41SQDRqc/220=</Q>" +
				"<G>FI6/VxOXyIMMW6i4dVJyQ27mVbzdehiprmfRnwT8cYM9Eho3BfLmv2rbiuEw8U0tJk/HzmppUKFNeWUK9xIpVg==</G>" +
				"<Y>yvGw6d2AB7YNp8LD/DJoMeWCRPf9piyn4u3LFv9I+8z4CN0nnrgkId2Vrgak+/dSD2bVmI87Rz0fS5Cj5/ikOw==</Y>" +
				"<J>AAAAASLj8uTWjQIgIxqoGQkvru1/EZyvE31USOvTd+kfdGk9f8e0QJgYg9VkzG/0</J>" +
				"<Seed>k+hx8OAOva6npEadsVeDmIDjo18=</Seed>" +
				"<PgenCounter>GQ==</PgenCounter>" +
				"<X>uLFTlRX12CsAj7p+2fnTaEWhqhc=</X>" +
				"</DSAKeyValue>";
			byte[] signature = new byte[] {
				0x30, 0x2C, 0x02, 0x14, 0x33, 0x4A, 0x7F, 0x1F,
				0xDA, 0x4F, 0x64, 0x65, 0x29, 0xDF, 0x59, 0x29,
				0xF5, 0x80, 0xED, 0x40, 0x8D, 0xAE, 0x26, 0x80,
				0x02, 0x14, 0x88, 0x5D, 0xE4, 0x18, 0xA0, 0xBB,
				0x85, 0xBD, 0x8E, 0xDC, 0xB3, 0xFF, 0x62, 0xE7,
				0x41, 0x25, 0x6A, 0x03, 0x68, 0x4F
			};
			
			SignatureAlgorithmDSA dsa = new SignatureAlgorithmDSA();
			DSACryptoServiceProvider key = (DSACryptoServiceProvider)
				dsa.ImportPrivateKey(System.Text.Encoding.ASCII.GetBytes(dsaKeys)).Algorithm;
			Assert.IsTrue (dsa.VerifyData(new byte[32], key, signature));
		}
	}
}

