//
// AaltoTLS.PluginInterface.CipherSuitePlugin
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

namespace AaltoTLS.PluginInterface
{
	public abstract class CipherSuitePlugin
	{
		public abstract string PluginName { get; }

		public virtual UInt16[] SupportedCipherSuites          { get { return new UInt16[0]; } }
		public virtual string[] SupportedKeyExchangeAlgorithms { get { return new string[0]; } }
		public virtual string[] SupportedSignatureAlgorithms   { get { return new string[0]; } }
		public virtual string[] SupportedPseudoRandomFunctions { get { return new string[0]; } }
		public virtual string[] SupportedBulkCipherAlgorithms  { get { return new string[0]; } }
		public virtual string[] SupportedMACAlgorithms         { get { return new string[0]; } }

		public virtual CipherSuiteInfo GetCipherSuiteFromID(UInt16 id)           { return null; }
		public virtual KeyExchangeAlgorithm GetKeyExchangeAlgorithm(string name) { return null; }
		public virtual SignatureAlgorithm GetSignatureAlgorithm(string name)     { return null; }
		public virtual PseudoRandomFunction GetPseudoRandomFunction(string name) { return null; }
		public virtual BulkCipherAlgorithm GetBulkCipherAlgorithm(string name)   { return null; }
		public virtual MACAlgorithm GetMACAlgorithm(string name)                 { return null; }

		public override string ToString() { return PluginName; }
	}
}
