//
// BaseCipherSuitePluginTest
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

namespace BaseCipherSuitePlugin
{
	[TestFixture]
	public class BaseCipherSuitePluginTest
	{
		[Test]
		public void Constructor ()
		{
			BaseCipherSuitePlugin plugin = new BaseCipherSuitePlugin();
			Assert.IsNotNull (plugin.PluginName);
			Assert.IsNotNull (plugin.SupportedCipherSuites);
			Assert.IsNotNull (plugin.SupportedKeyExchangeAlgorithms);
			Assert.IsNotNull (plugin.SupportedSignatureAlgorithms);
			Assert.IsNotNull (plugin.SupportedPseudoRandomFunctions);
			Assert.IsNotNull (plugin.SupportedBulkCipherAlgorithms);
			Assert.IsNotNull (plugin.SupportedMACAlgorithms);
			
			Assert.IsNotEmpty (plugin.SupportedCipherSuites);
			Assert.IsNotEmpty (plugin.SupportedKeyExchangeAlgorithms);
			Assert.IsNotEmpty (plugin.SupportedSignatureAlgorithms);
			Assert.IsNotEmpty (plugin.SupportedPseudoRandomFunctions);
			Assert.IsNotEmpty (plugin.SupportedBulkCipherAlgorithms);
			Assert.IsNotEmpty (plugin.SupportedMACAlgorithms);
		}
	}
}

