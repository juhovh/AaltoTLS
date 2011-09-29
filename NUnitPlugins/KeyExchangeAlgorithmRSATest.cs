//
// KeyExchangeAlgorithmRSATest
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
	public class KeyExchangeAlgorithmRSATest
	{
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void Constructor ()
		{
			KeyExchangeAlgorithmRSA keyex = new KeyExchangeAlgorithmRSA();
			Assert.IsTrue (keyex.SupportsProtocolVersion(ProtocolVersion.TLS1_0));
			Assert.IsTrue (keyex.SupportsProtocolVersion(ProtocolVersion.DTLS1_0));
			Assert.IsNull (keyex.GetServerKeys(ProtocolVersion.TLS1_0));
			
			keyex.ProcessServerKeys(ProtocolVersion.TLS1_0, null);
		}
		
		[Test]
		public void KeyExchangeTest ()
		{
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
			KeyExchangeAlgorithmRSA keyex = new KeyExchangeAlgorithmRSA();
			PseudoRandomFunctionTLSGeneric prf = new PseudoRandomFunctionTLSGeneric("SHA1");
			
			byte[] clientKeys = keyex.GetClientKeys(ProtocolVersion.TLS1_0, ProtocolVersion.TLS1_0, rsa);
			byte[] master1 = keyex.GetMasterSecret(prf, new byte[32]);
			keyex.ProcessClientKeys(ProtocolVersion.TLS1_0, ProtocolVersion.TLS1_0, new CertificatePrivateKey(keyex.CertificateKeyAlgorithm, rsa), clientKeys);
			byte[] master2 = keyex.GetMasterSecret(prf, new byte[32]);
			Assert.AreEqual (master1, master2);
			Assert.AreEqual (48, master2.Length);
		}
		
		[Test]
		public void ClientVersionInvalidTest ()
		{
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
			KeyExchangeAlgorithmRSA keyex = new KeyExchangeAlgorithmRSA();
			PseudoRandomFunctionTLSGeneric prf = new PseudoRandomFunctionTLSGeneric("SHA1");
			
			byte[] clientKeys = keyex.GetClientKeys(ProtocolVersion.TLS1_0, ProtocolVersion.TLS1_0, rsa);
			byte[] master1 = keyex.GetMasterSecret(prf, new byte[32]);
			keyex.ProcessClientKeys(ProtocolVersion.TLS1_0, ProtocolVersion.TLS1_2, new CertificatePrivateKey(keyex.CertificateKeyAlgorithm, rsa), clientKeys);
			byte[] master2 = keyex.GetMasterSecret(prf, new byte[32]);
			Assert.AreNotEqual (master1, master2);
		}
		
		[Test]
		public void VersionMismatchTest ()
		{
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
			KeyExchangeAlgorithmRSA keyex = new KeyExchangeAlgorithmRSA();
			PseudoRandomFunctionTLSGeneric prf = new PseudoRandomFunctionTLSGeneric("SHA1");
			
			byte[] clientKeys = keyex.GetClientKeys(ProtocolVersion.TLS1_0, ProtocolVersion.TLS1_0, rsa);
			byte[] master1 = keyex.GetMasterSecret(prf, new byte[32]);
			keyex.ProcessClientKeys(ProtocolVersion.SSL3_0, ProtocolVersion.TLS1_0, new CertificatePrivateKey(keyex.CertificateKeyAlgorithm, rsa), clientKeys);
			byte[] master2 = keyex.GetMasterSecret(prf, new byte[32]);
			Assert.AreNotEqual (master1, master2);
			
			clientKeys = keyex.GetClientKeys(ProtocolVersion.SSL3_0, ProtocolVersion.TLS1_0, rsa);
			master1 = keyex.GetMasterSecret(prf, new byte[32]);
			keyex.ProcessClientKeys(ProtocolVersion.TLS1_0, ProtocolVersion.TLS1_0, new CertificatePrivateKey(keyex.CertificateKeyAlgorithm, rsa), clientKeys);
			master2 = keyex.GetMasterSecret(prf, new byte[32]);
			Assert.AreNotEqual (master1, master2);
		}
		
		[Test]
		public void TestVector ()
		{
			byte[] encryptedKey = {
				0x00, 0x40, 0x51, 0x57, 0x5A, 0x26, 0x6D, 0xCC,
				0x65, 0x85, 0x55, 0xDE, 0x28, 0x01, 0x41, 0x62,
				0x13, 0x4F, 0x0A, 0xB4, 0xEF, 0x34, 0x99, 0x54,
				0x51, 0x9E, 0x4E, 0x6D, 0x21, 0x1B, 0xE9, 0x73,
				0x4C, 0xF8, 0x79, 0xF5, 0xBE, 0x71, 0x2D, 0x8F,
				0x22, 0xF7, 0x4E, 0x51, 0x49, 0x33, 0xD5, 0x0C,
				0x21, 0xC7, 0x17, 0xEE, 0x23, 0xA5, 0xD6, 0xA1,
				0x2C, 0x8D, 0xD2, 0x52, 0x5B, 0xE2, 0xC1, 0x10,
				0x8F, 0x14
			};
			string rsaKeys =
				"<RSAKeyValue>" +
				"<Modulus>nrum196jNc4CFruN2+6A/1S4XXdaYFDtuXuSVHUGfhINISX87ze7ASP4K4oq5qK8qux9wwndqB9ERD2ZuLBsfw==</Modulus>" +
				"<Exponent>EQ==</Exponent>" +
				"<P>/lOfBctf4yh0CwrxG1zJdQhjkLjq+ruy0uwJxiHolus=</P>" +
				"<Q>n8cEGYQH4J97W26zvq1xtXwKWDXpSDsPcSRijdYMw70=</Q>" +
				"<DP>wnwuT7mjrbWF6lOpUSjWSm/TqufCv7y17JZh07+TvrM=</DP>" +
				"<DQ>OGRbzMUv9Oz+XIFsnaagmmgDpqmdoQXJNv3IbkuMCNk=</DQ>" +
				"<InverseQ>xsbdvaSCbalm6wa8DtBMgOgWfbwPokwfnjQ1J0trre4=</InverseQ>" +
				"<D>QVxTwkydjqAe+k06aZ5xWhPTcce7zU6AARTDyGxsFcqIEb1qUN0pkAaWWE9dh+5pWyUQGyUhlFN4jc6kQE0HWQ==</D>" +
				"</RSAKeyValue>";
			byte[] masterSecret = {
				0xC9, 0xBC, 0x99, 0x08, 0xAA, 0x11, 0xFF, 0x63,
				0xBE, 0x01, 0xF4, 0x07, 0x0D, 0x37, 0x8E, 0xA0,
				0xE4, 0x1A, 0x30, 0x08, 0xAD, 0x08, 0xAC, 0xBA,
				0xEE, 0x37, 0xAA, 0xBD, 0x49, 0x28, 0x1C, 0xD6,
				0x7D, 0x2A, 0xBE, 0x55, 0x85, 0xA2, 0x30, 0x88,
				0xBE, 0xC9, 0xED, 0x76, 0x14, 0xDA, 0x6B, 0x1E
			};
			
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(512);
			rsa.FromXmlString(rsaKeys);
			KeyExchangeAlgorithmRSA keyex = new KeyExchangeAlgorithmRSA();
			PseudoRandomFunctionTLSGeneric prf = new PseudoRandomFunctionTLSGeneric("SHA1");
			
			keyex.ProcessClientKeys(ProtocolVersion.TLS1_0, ProtocolVersion.TLS1_0, new CertificatePrivateKey(keyex.CertificateKeyAlgorithm, rsa), encryptedKey);
			byte[] master = keyex.GetMasterSecret(prf, new byte[32]);
			Assert.AreEqual (masterSecret, master);
		}
		

	}
}

