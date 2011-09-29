//
// BaseCipherSuitePlugin
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
using System.Collections.Generic;
using AaltoTLS.PluginInterface;

namespace BaseCipherSuitePlugin
{
	public class BaseCipherSuitePlugin : CipherSuitePlugin
	{
		private readonly CipherSuiteInfo[] _cipherSuites = new CipherSuiteInfo[] {
			// Cipher suites from TLS 1.0 specification (excluding EXPORT and IDEA)
			new CipherSuiteInfo(0x0001, "TLS_RSA_WITH_NULL_MD5", "RSA", null, null, "MD5"),
			new CipherSuiteInfo(0x0002, "TLS_RSA_WITH_NULL_SHA", "RSA", null, null, "SHA1"),
			new CipherSuiteInfo(0x0004, "TLS_RSA_WITH_RC4_128_MD5", "RSA", null, "RC4_128", "MD5"),
			new CipherSuiteInfo(0x0005, "TLS_RSA_WITH_RC4_128_SHA", "RSA", null, "RC4_128", "SHA1"),
			new CipherSuiteInfo(0x0009, "TLS_RSA_WITH_DES_CBC_SHA", "RSA", null, "DES_CBC", "SHA1"),
			new CipherSuiteInfo(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", null, "3DES_EDE_CBC", "SHA1"),

			new CipherSuiteInfo(0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA", "DH", "DSA", "DES_CBC", "SHA1"),
			new CipherSuiteInfo(0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", "DH", "DSA", "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA", "DH", "RSA", "DES_CBC", "SHA1"),
			new CipherSuiteInfo(0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", "DH", "RSA", "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA", "DHE", "DSA", "DES_CBC", "SHA1"),
			new CipherSuiteInfo(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", "DHE", "DSA", "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", "DHE", "RSA", "DES_CBC", "SHA1"),
			new CipherSuiteInfo(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", "DHE", "RSA", "3DES_EDE_CBC", "SHA1"),
			
			new CipherSuiteInfo(0x0017, "TLS_DH_anon_WITH_DES_CBC_SHA", "DHE", null, "DES_CBC", "SHA1"),
			new CipherSuiteInfo(0x0018, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "DHE", null, "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0x0019, "TLS_DH_anon_WITH_DES_CBC_SHA", "DHE", null, "DES_CBC", "SHA1"),
			new CipherSuiteInfo(0x001A, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", "DHE", null, "3DES_EDE_CBC", "SHA1"),
			
			
			// Additional cipher suites from TLS 1.2 specification
			new CipherSuiteInfo(0x003B, "TLS_RSA_WITH_NULL_SHA256", "RSA", null, "TLS_SHA256", null, "SHA256"),
			new CipherSuiteInfo(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", null, "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", null, "AES_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", null, "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", null, "TLS_SHA256", "AES_256_CBC", "SHA256"),
			
			new CipherSuiteInfo(0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA", "DH", "DSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA", "DH", "RSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", "DHE", "DSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", "RSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA", "DH", "DSA", "AES_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA", "DH", "RSA", "AES_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", "DHE", "DSA", "AES_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", "RSA", "AES_256_CBC", "SHA1"),
			
			new CipherSuiteInfo(0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", "DH", "DSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", "DH", "RSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "DHE", "DSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", "RSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "DH", "DSA", "TLS_SHA256", "AES_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", "DH", "RSA", "TLS_SHA256", "AES_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", "DHE", "DSA", "TLS_SHA256", "AES_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", "RSA", "TLS_SHA256", "AES_256_CBC", "SHA256"),
			
			new CipherSuiteInfo(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", "DHE", null, "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA", "DHE", null, "AES_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256", "DHE", null, "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256", "DHE", null, "TLS_SHA256", "AES_256_CBC", "SHA256"),
			
			
			/* AES-GCM cipher suites from RFC 5288 */
			new CipherSuiteInfo(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", null, "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", null, "TLS_SHA384", "AES_256_GCM", null),
			new CipherSuiteInfo(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", "RSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", "RSA", "TLS_SHA384", "AES_256_GCM", null),
			new CipherSuiteInfo(0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", "DH", "RSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", "DH", "RSA", "TLS_SHA384", "AES_256_GCM", null),
			new CipherSuiteInfo(0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", "DHE", "DSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", "DHE", "DSA", "TLS_SHA384", "AES_256_GCM", null),
			new CipherSuiteInfo(0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", "DH", "DSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", "DH", "DSA", "TLS_SHA384", "AES_256_GCM", null),
		};


		public override string PluginName
		{
			get { return "Base cipher suite plugin"; }
		}

		public override UInt16[] SupportedCipherSuites
		{
			get {
				List<UInt16> suites = new List<UInt16>();
				foreach (CipherSuiteInfo info in _cipherSuites) {
					suites.Add(info.CipherSuiteID);
				}
				return suites.ToArray();
			}
		}

		public override string[] SupportedKeyExchangeAlgorithms
		{
			get { return new string[] { "RSA" }; }
		}

		public override string[] SupportedSignatureAlgorithms
		{
			get { return new string[] { "DSA" }; }
		}

		public override string[] SupportedPseudoRandomFunctions
		{
			get { return new string[] { "SSLv3", "TLSv1", "TLS_SHA256", "TLS_SHA384", "TLS_SHA512" }; }
		}

		public override string[] SupportedBulkCipherAlgorithms
		{
			get { return new string[] { "DES_CBC", "3DES_EDE_CBC", "AES_128_CBC", "AES_256_CBC", "AES_128_GCM", "AES_256_GCM" }; }
		}

		public override string[] SupportedMACAlgorithms
		{
			get { return new string[] { "SSLv3_MD5", "SSLv3_SHA1", "MD5", "SHA1", "SHA256", "SHA384", "SHA512" }; }
		}


		public override CipherSuiteInfo GetCipherSuiteFromID(UInt16 id)
		{
			foreach (CipherSuiteInfo cipherSuite in _cipherSuites) {
				if (cipherSuite.CipherSuiteID == id) {
					return cipherSuite;
				}
			}

			return null;
		}

		public override KeyExchangeAlgorithm GetKeyExchangeAlgorithm(string name)
		{
			if (name.Equals("RSA")) {
				return new KeyExchangeAlgorithmRSA();
			} else {
				return null;
			}
		}

		public override SignatureAlgorithm GetSignatureAlgorithm(string name)
		{
			if (name.Equals("DSA")) {
				return new SignatureAlgorithmDSA();
			} else {
				return null;
			}
		}

		public override PseudoRandomFunction GetPseudoRandomFunction(string name)
		{
			if (name.Equals("SSLv3")) {
				return new PseudoRandomFunctionSSLv3();
			} else if (name.Equals("TLSv1")) {
				return new PseudoRandomFunctionTLSv1();
			} else if (name.Equals("TLS_SHA256")) {
				return new PseudoRandomFunctionTLSGeneric("SHA256");
			} else if (name.Equals("TLS_SHA384")) {
				return new PseudoRandomFunctionTLSGeneric("SHA384");
			} else if (name.Equals("TLS_SHA512")) {
				return new PseudoRandomFunctionTLSGeneric("SHA512");
			} else {
				return null;
			}
		}

		public override BulkCipherAlgorithm GetBulkCipherAlgorithm(string name)
		{
			if (name.Equals("DES_CBC")) {
				return new BulkCipherAlgorithmDES();
			} else if (name.Equals("3DES_EDE_CBC")) {
				return new BulkCipherAlgorithm3DES();
			} else if (name.Equals("AES_128_CBC")) {
				return new BulkCipherAlgorithmAES(128);
			} else if (name.Equals("AES_256_CBC")) {
				return new BulkCipherAlgorithmAES(256);
			} else if (name.Equals("AES_128_GCM")) {
				return new BulkCipherAlgorithmAesGcm(128);
			} else if (name.Equals("AES_256_GCM")) {
				return new BulkCipherAlgorithmAesGcm(256);
			} else {
				return null;
			}
		}

		public override MACAlgorithm GetMACAlgorithm(string name)
		{
			if (name.Equals("SSLv3_MD5")) {
				return new MACAlgorithmSSLv3(false);
			} else if (name.Equals("SSLv3_SHA1")) {
				return new MACAlgorithmSSLv3(true);
			} else if (name.Equals("MD5")) {
				return new MACAlgorithmMD5();
			} else if (name.Equals("SHA1")) {
				return new MACAlgorithmSHA1();
			} else if (name.Equals("SHA256")) {
				return new MACAlgorithmSHA256();
			} else if (name.Equals("SHA384")) {
				return new MACAlgorithmSHA384();
			} else if (name.Equals("SHA512")) {
				return new MACAlgorithmSHA512();
			} else {
				return null;
			}
		}
	}
}
