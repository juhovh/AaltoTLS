//
// AaltoTLS.PluginInterface.CipherSuite
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

namespace AaltoTLS.PluginInterface
{
	public class CipherSuite
	{
		public readonly ProtocolVersion ProtocolVersion;
		public readonly UInt16 CipherSuiteID;
		public readonly string CipherSuiteName;

		private KeyExchangeAlgorithm _keyExchangeAlgorithm;
		private SignatureAlgorithm   _signatureAlgorithm;
		private PseudoRandomFunction _pseudoRandomFunction;
		private BulkCipherAlgorithm  _bulkCipherAlgorithm;
		private MACAlgorithm         _macAlgorithm;
		
		public bool IsAnonymous
		{
			get { return (KeyExchangeAlgorithm.CertificateKeyAlgorithm == null && SignatureAlgorithm.CertificateKeyAlgorithm == null); }
		}
		
		public KeyExchangeAlgorithm KeyExchangeAlgorithm
		{
			get { return _keyExchangeAlgorithm; }
			internal set { _keyExchangeAlgorithm = value; }
		}

		public SignatureAlgorithm SignatureAlgorithm
		{
			get { return _signatureAlgorithm; }
			internal set { _signatureAlgorithm = value; }
		}

		public PseudoRandomFunction PseudoRandomFunction
		{
			get { return _pseudoRandomFunction; }
			internal set { _pseudoRandomFunction = value; }
		}

		public BulkCipherAlgorithm BulkCipherAlgorithm
		{
			get { return _bulkCipherAlgorithm; }
			internal set { _bulkCipherAlgorithm = value; }
		}

		public MACAlgorithm MACAlgorithm
		{
			get { return _macAlgorithm; }
			internal set { _macAlgorithm = value; }
		}
		
		public CipherSuite(ProtocolVersion version)
		{
			ProtocolVersion = version;
			CipherSuiteID = 0x0000;
			CipherSuiteName = "TLS_NULL_WITH_NULL_NULL";
			
			_keyExchangeAlgorithm = new KeyExchangeAlgorithmNull();
			_signatureAlgorithm = new SignatureAlgorithmNull();
			_pseudoRandomFunction = null;
			_bulkCipherAlgorithm = new BulkCipherAlgorithmNull();
			_macAlgorithm = new MACAlgorithmNull();
		}

		public CipherSuite(ProtocolVersion version, UInt16 id, string csName)
		{
			ProtocolVersion = version;
			CipherSuiteID = id;
			CipherSuiteName = csName;
		}
	}
}
