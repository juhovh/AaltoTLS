//
// BouncyCastleCipherSuitePlugin
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

using Org.BouncyCastle.Crypto.Engines;

namespace BouncyCastleCipherSuitePlugin
{
	public class BouncyCastleCipherSuitePlugin : CipherSuitePlugin
	{
		private readonly CipherSuiteInfo[] _cipherSuites = new CipherSuiteInfo[] {
			// SEED cipher suites from RFC4162
			new CipherSuiteInfo(0x0096, "TLS_RSA_WITH_SEED_CBC_SHA", "RSA", null, "SEED_CBC", "SHA1"),
			new CipherSuiteInfo(0x0096, "TLS_DH_DSS_WITH_SEED_CBC_SHA", "DH", "DSA", "SEED_CBC", "SHA1"),
			new CipherSuiteInfo(0x0096, "TLS_DH_RSA_WITH_SEED_CBC_SHA", "DH", "RSA", "SEED_CBC", "SHA1"),
			new CipherSuiteInfo(0x0096, "TLS_DHE_DSS_WITH_SEED_CBC_SHA", "DHE", "DSA", "SEED_CBC", "SHA1"),
			new CipherSuiteInfo(0x0096, "TLS_DHE_RSA_WITH_SEED_CBC_SHA", "DHE", "RSA", "SEED_CBC", "SHA1"),
			new CipherSuiteInfo(0x0096, "TLS_DH_anon_WITH_SEED_CBC_SHA", "DHE", null, "SEED_CBC", "SHA1"),
			
			
			
			// Camellia cipher suites from RFC5932
			new CipherSuiteInfo(0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", "RSA", null, "CAMELLIA_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", "DH", "DSA", "CAMELLIA_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", "DH", "RSA", "CAMELLIA_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", "DHE", "DSA", "CAMELLIA_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", "DHE", "RSA", "CAMELLIA_128_CBC", "SHA1"),
			new CipherSuiteInfo(0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", "DHE", null, "CAMELLIA_128_CBC", "SHA1"),

			new CipherSuiteInfo(0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", "RSA", null, "CAMELLIA_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", "DH", "DSA", "CAMELLIA_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", "DH", "RSA", "CAMELLIA_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", "DHE", "DSA", "CAMELLIA_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", "DHE", "RSA", "CAMELLIA_256_CBC", "SHA1"),
			new CipherSuiteInfo(0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", "DHE", null, "CAMELLIA_256_CBC", "SHA1"),

			new CipherSuiteInfo(0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", "RSA", null, "TLS_SHA256", "CAMELLIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x00BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", "DH", "DSA", "TLS_SHA256", "CAMELLIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x00BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", "DH", "RSA", "TLS_SHA256", "CAMELLIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x00BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", "DHE", "DSA", "TLS_SHA256", "CAMELLIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", "DHE", "RSA", "TLS_SHA256", "CAMELLIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0x00BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", "DHE", null, "TLS_SHA256", "CAMELLIA_128_CBC", "SHA256"),

			new CipherSuiteInfo(0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", "RSA", null, "TLS_SHA256", "CAMELLIA_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x00C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", "DH", "DSA", "TLS_SHA256", "CAMELLIA_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x00C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", "DH", "RSA", "TLS_SHA256", "CAMELLIA_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x00C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", "DHE", "DSA", "TLS_SHA256", "CAMELLIA_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", "DHE", "RSA", "TLS_SHA256", "CAMELLIA_256_CBC", "SHA256"),
			new CipherSuiteInfo(0x00C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", "DHE", null, "TLS_SHA256", "CAMELLIA_256_CBC", "SHA256"),
			
			
			
			// Elliptic Curve cipher suites
			new CipherSuiteInfo(0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA", "ECDH", "ECDSA", null, "SHA1"),
			new CipherSuiteInfo(0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "ECDH", "ECDSA", "RC4_128", "SHA1"),
			new CipherSuiteInfo(0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDH", "ECDSA", "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", "ECDH", "ECDSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", "ECDH", "ECDSA", "AES_256_CBC", "SHA1"),

			new CipherSuiteInfo(0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", "ECDHE", "ECDSA", null, "SHA1"),
			new CipherSuiteInfo(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "ECDHE", "ECDSA", "RC4_128", "SHA1"),
			new CipherSuiteInfo(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "ECDSA", "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", "ECDSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", "ECDSA", "AES_256_CBC", "SHA1"),

			new CipherSuiteInfo(0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA", "ECDH", "RSA", null, "SHA1"),
			new CipherSuiteInfo(0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA", "ECDH", "RSA", "RC4_128", "SHA1"),
			new CipherSuiteInfo(0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", "ECDH", "RSA", "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", "ECDH", "RSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", "ECDH", "RSA", "AES_256_CBC", "SHA1"),

			new CipherSuiteInfo(0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA", "ECDHE", "RSA", null, "SHA1"),
			new CipherSuiteInfo(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", "ECDHE", "RSA", "RC4_128", "SHA1"),
			new CipherSuiteInfo(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE", "RSA", "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", "RSA", "AES_256_CBC", "SHA1"),

			new CipherSuiteInfo(0xC015, "TLS_ECDH_anon_WITH_NULL_SHA", "ECDHE", null, null, "SHA1"),
			new CipherSuiteInfo(0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA", "ECDHE", null, "RC4_128", "SHA1"),
			new CipherSuiteInfo(0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", "ECDHE", null, "3DES_EDE_CBC", "SHA1"),
			new CipherSuiteInfo(0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "ECDHE", null, "AES_128_CBC", "SHA1"),
			new CipherSuiteInfo(0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "ECDHE", null, "AES_256_CBC", "SHA1"),
			
			// These are from RFC 5289 for use with TLS 1.2 only
			new CipherSuiteInfo(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "ECDSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "ECDSA", "TLS_SHA384", "AES_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "ECDHE", "ECDSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", "ECDHE", "ECDSA", "TLS_SHA384", "AES_256_CBC", "SHA384"),
			
			new CipherSuiteInfo(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "TLS_SHA384", "AES_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA", "TLS_SHA256", "AES_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA", "TLS_SHA384", "AES_256_CBC", "SHA384"),
			
			new CipherSuiteInfo(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "TLS_SHA384", "AES_256_GCM", null),
			new CipherSuiteInfo(0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", "ECDSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", "ECDSA", "TLS_SHA384", "AES_256_GCM", null),
			
			new CipherSuiteInfo(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "TLS_SHA384", "AES_256_GCM", null),
			new CipherSuiteInfo(0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "TLS_SHA256", "AES_128_GCM", null),
			new CipherSuiteInfo(0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "TLS_SHA384", "AES_256_GCM", null),
		};
		
		public override string PluginName
		{
			get { return "BouncyCastle cipher suite plugin (SEED, Camellia, ECDH, ECDSA)"; }
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
		/*
		public override string[] SupportedKeyExchangeAlgorithms
		{
			get { return new string[] { "ECDHE" }; }
		}

		public override string[] SupportedSignatureAlgorithms
		{
			get { return new string[] { "ECDSA" }; }
		}
		*/
		public override string[] SupportedBulkCipherAlgorithms
		{
			get { return new string[] { "SEED_CBC", "CAMELLIA_128_CBC", "CAMELLIA_256_CBC" }; }
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
		/*
		public override KeyExchangeAlgorithm GetKeyExchangeAlgorithm(string name)
		{
			if (name.Equals("ECDHE")) {
				return new KeyExchangeAlgorithmECDHE();
			} else {
				return null;
			}
		}

		public override SignatureAlgorithm GetSignatureAlgorithm(string name)
		{
			if (name.Equals("ECDSA")) {
				return new SignatureAlgorithmECDSA();
			} else {
				return null;
			}
		}
		*/
		public override BulkCipherAlgorithm GetBulkCipherAlgorithm(string name)
		{
			if (name.Equals("SEED_CBC")) {
				return new BulkCipherAlgorithmCbc<SeedEngine>(128);
			} else if (name.Equals("CAMELLIA_128_CBC")) {
				return new BulkCipherAlgorithmCbc<CamelliaEngine>(128);
			} else if (name.Equals("CAMELLIA_256_CBC")) {
				return new BulkCipherAlgorithmCbc<CamelliaEngine>(256);
			} else {
				return null;
			}
		}
	}
}

