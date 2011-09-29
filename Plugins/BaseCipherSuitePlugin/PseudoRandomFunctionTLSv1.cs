//
// PseudoRandomFunctionTLSv1
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
	internal sealed class MD5SHA1CryptoServiceProvider : HashAlgorithm
	{
		private HashAlgorithm _md5;
		private HashAlgorithm _sha1;

		public MD5SHA1CryptoServiceProvider()
		{
			this.HashSizeValue = 288;
			_md5 = new MD5CryptoServiceProvider();
			_sha1 = new SHA1CryptoServiceProvider();
		}

		~MD5SHA1CryptoServiceProvider()
		{
			/* This will call Dispose */
			Clear();
		}

		public override void Initialize()
		{
			_md5.Initialize();
			_sha1.Initialize();
		}

		protected override void Dispose(bool disposing)
		{
			_md5.Clear();
			_sha1.Clear();
		}

		protected override void HashCore(byte[] array, int ibStart, int cbSize)
		{
			_md5.TransformBlock(array, ibStart, cbSize, array, ibStart);
			_sha1.TransformBlock(array, ibStart, cbSize, array, ibStart);
		}

		protected override byte[] HashFinal()
		{
			byte[] hash = new byte[36];
			
			_md5.TransformFinalBlock(new byte[0], 0, 0);
			_sha1.TransformFinalBlock(new byte[0], 0, 0);

			Array.Copy(_md5.Hash, 0, hash, 0, 16);
			Array.Copy(_sha1.Hash, 0, hash, 16, 20);

			return hash;
		}
	}
	
	internal sealed class TLSv1DeriveBytes : DeriveBytes
	{
		private HMAC _md5HMAC;
		private HMAC _sha1HMAC;
		private byte[] _seed;

		private byte[] _md5Ai;
		private byte[] _md5Hash;

		private byte[] _sha1Ai;
		private byte[] _sha1Hash;

		public TLSv1DeriveBytes(byte[] secret, byte[] seed)
		{
			/* Original secret is divided into half */
			int secretLength = (secret.Length + 1) / 2;

			/* Construct the secret for MD5 hashing */
			byte[] md5Secret = new byte[secretLength];
			Array.Copy(secret, 0, md5Secret, 0, secretLength);

			/* Construct the secret for SHA1 hashing */
			byte[] sha1Secret = new byte[secretLength];
			Array.Copy(secret, secret.Length - secretLength, sha1Secret, 0, secretLength);

			/* Initialize HMAC objects using the secret */
			_md5HMAC = new HMACMD5(md5Secret);
			_sha1HMAC = new HMACSHA1(sha1Secret);

			/* Set the seed as our parameter */
			_seed = seed;

			/* Reset the HMAC generators */
			Reset();
		}

		public override void Reset() {
			_md5HMAC.Initialize();
			_md5Ai = _md5HMAC.ComputeHash(_seed);
			_md5Hash = new byte[0];

			_sha1HMAC.Initialize();
			_sha1Ai = _sha1HMAC.ComputeHash(_seed);
			_sha1Hash = new byte[0];
		}

		private byte[] GetMD5Bytes(int count) {
			byte[] ret = new byte[count];

			int filled = 0;
			while (filled < count) {
				if (filled + _md5Hash.Length < count) {
					/* Copy current hash into results */
					Array.Copy(_md5Hash, 0, ret, filled, _md5Hash.Length);
					filled += _md5Hash.Length;

					/* Calculate the next hash */
					_md5HMAC.Initialize();
					_md5HMAC.TransformBlock(_md5Ai, 0, _md5HMAC.HashSize/8, _md5Ai, 0);
					_md5HMAC.TransformFinalBlock(_seed, 0, _seed.Length);
					_md5Hash = _md5HMAC.Hash;

					_md5HMAC.Initialize();
					_md5Ai = _md5HMAC.ComputeHash(_md5Ai);
				} else {
					/* Count how many bytes to consume */
					int consumed = count - filled;

					/* Make a partial copy of the current hash */
					Array.Copy(_md5Hash, 0, ret, filled, consumed);
					filled += consumed;

					/* Remove read bytes from the current hash */
					byte[] tmp = new byte[_md5Hash.Length - consumed];
					Array.Copy(_md5Hash, _md5Hash.Length - tmp.Length, tmp, 0, tmp.Length);
					_md5Hash = tmp;
				}
			}

			return ret;
		}

		private byte[] GetSHA1Bytes(int count) {
			byte[] ret = new byte[count];

			int filled = 0;
			while (filled < ret.Length) {
				if (filled + _sha1Hash.Length < count) {
					/* Copy current hash into results */
					Array.Copy(_sha1Hash, 0, ret, filled, _sha1Hash.Length);
					filled += _sha1Hash.Length;

					/* Calculate the next hash */
					_sha1HMAC.Initialize();
					_sha1HMAC.TransformBlock(_sha1Ai, 0, _sha1HMAC.HashSize/8, _sha1Ai, 0);
					_sha1HMAC.TransformFinalBlock(_seed, 0, _seed.Length);
					_sha1Hash = _sha1HMAC.Hash;

					_sha1HMAC.Initialize();
					_sha1Ai = _sha1HMAC.ComputeHash(_sha1Ai);
				} else {
					/* Count how many bytes to consume */
					int consumed = count - filled;

					/* Make a partial copy of the current hash */
					Array.Copy(_sha1Hash, 0, ret, filled, consumed);
					filled += consumed;

					/* Remove read bytes from the current hash */
					byte[] tmp = new byte[_sha1Hash.Length - consumed];
					Array.Copy(_sha1Hash, _sha1Hash.Length - tmp.Length, tmp, 0, tmp.Length);
					_sha1Hash = tmp;
				}
			}

			return ret;
		}

		public override byte[] GetBytes(int count) {
			byte[] ret = new byte[count];

			byte[] md5 = GetMD5Bytes(count);
			byte[] sha1 = GetSHA1Bytes(count);
			for (int i=0; i<ret.Length; i++) {
				ret[i] = (byte) (md5[i] ^ sha1[i]);
			}

			return ret;
		}
	}

	public class PseudoRandomFunctionTLSv1 : PseudoRandomFunction
	{
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			if (version == ProtocolVersion.TLS1_0 ||
			    version == ProtocolVersion.TLS1_1 || version == ProtocolVersion.DTLS1_0) {
				return true;
			}
			return false;
		}
		
		public override HashAlgorithm CreateVerifyHashAlgorithm(byte[] secret)
		{
			return new MD5SHA1CryptoServiceProvider();
		}
		
		public override int VerifyDataLength
		{
			get { return 12; }
		}

		public override DeriveBytes CreateDeriveBytes(byte[] secret, byte[] seed)
		{
			return new TLSv1DeriveBytes(secret, seed);
		}
	}
}
