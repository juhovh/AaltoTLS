//
// ARIACipherSuitePlugin
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

namespace ARIACipherSuitePlugin
{
	public class ARIACipherSuitePlugin : CipherSuitePlugin
	{
		private readonly CipherSuiteInfo[] _cipherSuites = new CipherSuiteInfo[] {
			new CipherSuiteInfo(0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256", "RSA", null, "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384", "RSA", null, "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC03E, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", "DH", "DSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC03F, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", "DH", "DSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", "DH", "RSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", "DH", "RSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", "DHE", "DSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", "DHE", "DSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", "DHE", "RSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", "DHE", "RSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", "DHE", null, "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", "DHE", null, "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			
			new CipherSuiteInfo(0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", "ECDHE", "ECDSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", "ECDHE", "ECDSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", "ECDH", "ECDSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", "ECDH", "ECDSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", "ECDHE", "RSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", "ECDHE", "RSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			new CipherSuiteInfo(0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", "ECDH", "RSA", "TLS_SHA256", "ARIA_128_CBC", "SHA256"),
			new CipherSuiteInfo(0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", "ECDH", "RSA", "TLS_SHA384", "ARIA_256_CBC", "SHA384"),
			
			new CipherSuiteInfo(0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256", "RSA", null, "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384", "RSA", null, "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC052, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", "DH", "DSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC053, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", "DH", "DSA", "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", "DH", "RSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", "DH", "RSA", "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", "DHE", "DSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", "DHE", "DSA", "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC058, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", "DHE", "RSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC059, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", "DHE", "RSA", "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC05A, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", "DHE", null, "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC05B, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", "DHE", null, "TLS_SHA384", "ARIA_256_GCM", null),
			
			new CipherSuiteInfo(0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", "ECDHE", "ECDSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", "ECDHE", "ECDSA", "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", "ECDH", "ECDSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", "ECDH", "ECDSA", "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", "ECDHE", "RSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", "ECDHE", "RSA", "TLS_SHA384", "ARIA_256_GCM", null),
			new CipherSuiteInfo(0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", "ECDH", "RSA", "TLS_SHA256", "ARIA_128_GCM", null),
			new CipherSuiteInfo(0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", "ECDH", "RSA", "TLS_SHA384", "ARIA_256_GCM", null),
			
		};
		
		public override string PluginName
		{
			get { return "ARIA (CBC and GCM) cipher plugin"; }
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

		public override string[] SupportedBulkCipherAlgorithms
		{
			get { return new string[] { "ARIA_128_CBC", "ARIA_256_CBC", "ARIA_128_GCM", "ARIA_256_GCM" }; }
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

		public override BulkCipherAlgorithm GetBulkCipherAlgorithm(string name)
		{
			if (name.Equals("ARIA_128_CBC")) {
				return new BulkCipherAlgorithmAria(128);
			} else if (name.Equals("ARIA_256_CBC")) {
				return new BulkCipherAlgorithmAria(256);
			} else if (name.Equals("ARIA_128_GCM")) {
				return new BulkCipherAlgorithmAriaGcm(128, 128);
			} else if (name.Equals("ARIA_256_GCM")) {
				return new BulkCipherAlgorithmAriaGcm(256, 128);
			} else {
				return null;
			}
		}
	}
}
