//
// AaltoTLS.PluginInterface.CertificatePrivateKey
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
using System.Security.Cryptography;

namespace AaltoTLS.PluginInterface
{
	public class CertificatePrivateKey
	{
		private string _oid;
		private byte[] _keyValue;
		private AsymmetricAlgorithm _algorithm;
		
		public CertificatePrivateKey(string oid, byte[] keyValue)
		{
			if (oid == null)
				throw new ArgumentNullException("oid");
			if (keyValue == null)
				throw new ArgumentNullException("keyValue");
			
			_oid = oid;
			_keyValue = keyValue;
		}
		
		public CertificatePrivateKey(string oid, AsymmetricAlgorithm algorithm)
		{
			if (oid == null)
				throw new ArgumentNullException("oid");
			if (algorithm == null)
				throw new ArgumentNullException("algorithm");
			
			_oid = oid;
			_algorithm = algorithm;
		}
		
		public string Oid
		{
			get { return _oid; }
		}
		
		public byte[] KeyValue
		{
			get {
				if (_keyValue == null) return null;
				return (byte[]) _keyValue.Clone();
			}
		}
		
		public AsymmetricAlgorithm Algorithm
		{
			get {
				return _algorithm;
			}
		}
	}
}

