//
// MACAlgorithmSSLv3
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
using AaltoTLS.PluginInterface;

namespace BaseCipherSuitePlugin
{
	internal sealed class HMACSSLv3 : KeyedHashAlgorithm
	{
		private HashAlgorithm _hashAlgorithm;
		private int _padSize;
		
		public HMACSSLv3(byte[] key, bool useSHA1)
		{
			if (useSHA1) {
				_hashAlgorithm = new SHA1CryptoServiceProvider();
				_padSize = 40;
			} else {
				_hashAlgorithm = new MD5CryptoServiceProvider();
				_padSize = 48;
			}
			
			KeyValue = (byte[]) key.Clone();
			HashSizeValue = _hashAlgorithm.HashSize;
		}
		
		public override void Initialize()
		{
			byte[] padding = new byte[_padSize];
			for (int i=0; i<padding.Length; i++) {
				padding[i] = 0x36;
			}
			
			_hashAlgorithm.Initialize();
			_hashAlgorithm.TransformBlock(KeyValue, 0, KeyValue.Length, KeyValue, 0);
			_hashAlgorithm.TransformBlock(padding, 0, padding.Length, padding, 0);
		}
		
		protected override void HashCore(byte[] rgb, int ib, int cb)
		{
			_hashAlgorithm.TransformBlock(rgb, ib, cb, rgb, ib);
		}
		
		protected override byte[] HashFinal()
		{
			byte[] padding = new byte[_padSize];
			for (int i=0; i<padding.Length; i++) {
				padding[i] = 0x5C;
			}
			
			// Finish the inner hash
			_hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);
			byte[] innerHash = _hashAlgorithm.Hash;
			
			// Finish the outer hash
			_hashAlgorithm.Initialize();
			_hashAlgorithm.TransformBlock(KeyValue, 0, KeyValue.Length, KeyValue, 0);
			_hashAlgorithm.TransformBlock(padding, 0, padding.Length, padding, 0);
			_hashAlgorithm.TransformFinalBlock(innerHash, 0, innerHash.Length);
			byte[] outerHash = _hashAlgorithm.Hash;
			
			return outerHash;
		}
	}

	public class MACAlgorithmSSLv3 : MACAlgorithm
	{
		private bool _useSHA1;
		
		public MACAlgorithmSSLv3(bool useSHA1)
		{
			_useSHA1 = useSHA1;
		}
	
		public override int HashSize
		{
			get { return (_useSHA1 ? 20 : 16); }
		}

		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}

		public override KeyedHashAlgorithm CreateHasher(byte[] key)
		{
			return new HMACSSLv3(key, _useSHA1);
		}
	}
}
