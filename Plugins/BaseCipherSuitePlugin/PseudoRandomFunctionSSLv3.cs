//
// PseudoRandomFunctionSSLv3
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
	internal sealed class HMACSSLv3Verify : KeyedHashAlgorithm
	{
		private MD5  _md5;
		private SHA1 _sha1;
		
		public HMACSSLv3Verify(byte[] key)
		{
			this.HashSizeValue = 288;
			this.KeyValue = (byte[]) key.Clone();
			
			_md5 = new MD5CryptoServiceProvider();
			_sha1 = new SHA1CryptoServiceProvider();
		}
		
		public override void Initialize()
		{
			_md5.Initialize();
			_sha1.Initialize();
		}
		
		protected override void HashCore(byte[] rgb, int ib, int cb)
		{
			_md5.TransformBlock(rgb, ib, cb, rgb, ib);
			_sha1.TransformBlock(rgb, ib, cb, rgb, ib);
		}
		
		protected override byte[] HashFinal()
		{
			byte[] md5Hash, sha1Hash;
			
			byte[] pad1 = new byte[48];
			byte[] pad2 = new byte[48];
			for (int i=0; i<48; i++) {
				pad1[i] = 0x36;
				pad2[i] = 0x5C;
			}
			
			/* Inner MD5 hash */
			_md5.TransformBlock(KeyValue, 0, KeyValue.Length, KeyValue, 0);
			_md5.TransformFinalBlock(pad1, 0, 48);
			md5Hash = _md5.Hash;
			
			/* Inner SHA1 hash */
			_sha1.TransformBlock(KeyValue, 0, KeyValue.Length, KeyValue, 0);
			_sha1.TransformFinalBlock(pad1, 0, 40);
			sha1Hash = _sha1.Hash;
			
			/* Outer MD5 hash */
			_md5.Initialize();
			_md5.TransformBlock(KeyValue, 0, KeyValue.Length, KeyValue, 0);
			_md5.TransformBlock(pad2, 0, 48, pad2, 0);
			_md5.TransformFinalBlock(md5Hash, 0, 16);
			md5Hash = _md5.Hash;

			/* Outer SHA1 hash */
			_sha1.Initialize();
			_sha1.TransformBlock(KeyValue, 0, KeyValue.Length, KeyValue, 0);
			_sha1.TransformBlock(pad2, 0, 40, pad2, 0);
			_sha1.TransformFinalBlock(sha1Hash, 0, 20);
			sha1Hash = _sha1.Hash;

			byte[] verifyData = new byte[36];
			Buffer.BlockCopy(md5Hash, 0, verifyData, 0, 16);
			Buffer.BlockCopy(sha1Hash, 0, verifyData, 16, 20);
			return verifyData;
		}
	}
	
	internal sealed class SSLv3DeriveBytes : DeriveBytes
	{
		private MD5 _md5;
		private SHA1 _sha1;
		
		private byte[] _secret;
		private byte[] _seed;
		
		private byte[] _hash;
		private int _iteration;

		public SSLv3DeriveBytes(byte[] secret, byte[] seed)
		{
			if (secret == null)
				throw new ArgumentNullException("secret");
			if (seed == null)
				throw new ArgumentNullException("seed");
			
			_secret = secret;
			_seed = seed;
			
			_md5 = new MD5CryptoServiceProvider();
			_sha1 = new SHA1CryptoServiceProvider();
			
			Reset();
		}

		public override void Reset() {
			_hash = new byte[0];
			_iteration = 1;
		}

		public override byte[] GetBytes(int count) {
			byte[] ret = new byte[count];

			int filled = 0;
			while (filled < count) {
				if (filled + _hash.Length < count) {
					/* Copy current hash into results */
					Array.Copy(_hash, 0, ret, filled, _hash.Length);
					filled += _hash.Length;

					/* Calculate the next hash */
					if (_iteration > 26) {
						throw new Exception("SSL3 pseudorandom function can't output more bytes");
					}
					
					byte[] header = new byte[_iteration];
					for (int i=0; i<header.Length; i++) {
						header[i] = (byte)(64 + _iteration);
					}

					_sha1.Initialize();
					_sha1.TransformBlock(header, 0, header.Length, header, 0);
					_sha1.TransformBlock(_secret, 0, _secret.Length, _secret, 0);
					_sha1.TransformFinalBlock(_seed, 0, _seed.Length);
					byte[] sha1Hash = _sha1.Hash;
					
					_md5.Initialize();
					_md5.TransformBlock(_secret, 0, _secret.Length, _secret, 0);
					_md5.TransformFinalBlock(sha1Hash, 0, sha1Hash.Length);
					_hash = _md5.Hash;

					_iteration++;
				} else {
					/* Count how many bytes to consume */
					int consumed = count - filled;

					/* Make a partial copy of the current hash */
					Array.Copy(_hash, 0, ret, filled, consumed);
					filled += consumed;

					/* Remove read bytes from the current hash */
					byte[] tmp = new byte[_hash.Length - consumed];
					Array.Copy(_hash, _hash.Length - tmp.Length, tmp, 0, tmp.Length);
					_hash = tmp;
				}
			}

			return ret;
		}
	}

	public class PseudoRandomFunctionSSLv3 : PseudoRandomFunction
	{
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return (version == ProtocolVersion.SSL3_0);
		}
		
		public override HashAlgorithm CreateVerifyHashAlgorithm(byte[] secret)
		{
			return new HMACSSLv3Verify(secret);
		}

		public override int VerifyDataLength
		{
			get { return 36; }
		}

		public override DeriveBytes CreateDeriveBytes(byte[] secret, string label, byte[] seed)
		{
			/* We need to ignore label in SSLv3 */
			return CreateDeriveBytes(secret, seed);
		}

		public override DeriveBytes CreateDeriveBytes(byte[] secret, byte[] seed)
		{
			return new SSLv3DeriveBytes(secret, seed);
		}
	}
}
