//
// AaltoTLS.PluginInterface.CertificatePublicKey
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
using System.Security.Cryptography.X509Certificates;

namespace AaltoTLS.PluginInterface
{
	public class CertificatePublicKey
	{
		private string _oid;
		private byte[] _parameters;
		private byte[] _keyValue;
		
		public CertificatePublicKey(X509Certificate certificate)
		{
			_oid = certificate.GetKeyAlgorithm();
			_parameters = certificate.GetKeyAlgorithmParameters();
			_keyValue = certificate.GetPublicKey();
		}
		
		public string Oid
		{
			get { return _oid; }
		}
		
		public byte[] Parameters
		{
			get { return (byte[]) _parameters.Clone(); }
		}
		
		public byte[] KeyValue
		{
			get { return (byte[]) _keyValue.Clone(); }
		}
		
		public virtual AsymmetricAlgorithm Algorithm
		{
			get {
				PublicKey publicKey = new PublicKey(new Oid(_oid),
				                                    new AsnEncodedData(_parameters),
				                                    new AsnEncodedData(_keyValue));
				return publicKey.Key;
			}
		}
	}
}
