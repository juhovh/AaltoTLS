//
// BigIntegerCipherSuitePlugin
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

namespace BigIntegerCipherSuitePlugin
{
	public class BigIntegerCipherSuitePlugin : CipherSuitePlugin
	{
		public override string PluginName
		{
			get { return "BigInteger cipher suite plugin (DH and RSA signature)"; }
		}

		public override string[] SupportedKeyExchangeAlgorithms
		{
			get { return new string[] { "DHE" }; }
		}

		public override string[] SupportedSignatureAlgorithms
		{
			get { return new string[] { "RSA" }; }
		}

		public override KeyExchangeAlgorithm GetKeyExchangeAlgorithm(string name)
		{
			if (name.Equals("DHE")) {
				return new KeyExchangeAlgorithmDHE();
			} else {
				return null;
			}
		}

		public override SignatureAlgorithm GetSignatureAlgorithm(string name)
		{
			if (name.Equals("RSA")) {
				return new SignatureAlgorithmRSA();
			} else {
				return null;
			}
		}
	}
}
