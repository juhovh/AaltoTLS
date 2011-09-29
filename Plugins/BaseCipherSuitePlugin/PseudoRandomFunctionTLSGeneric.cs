//
// PseudoRandomFunctionTLSGeneric
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
	internal enum TLSGenericType
	{
		MD5,
		SHA1,
		SHA256,
		SHA384,
		SHA512
	}
	
	// --- THIS IS AN UGLY WORKAROUND FOR MONO RUNTIME ---
	// As of 2011-09-21 mono HMACSHA384 and HMACSHA512 are broken
	// for key lengths between 65 and 128. This is not a problem
	// in MAC calculation, because the key length never goes over
	// 64 bytes, but it is a problem in PRF during master secret
	// generation. Therefore keeping this here is recommended.
	internal sealed class HMACGeneric : KeyedHashAlgorithm
	{
		private HashAlgorithm _hashAlgorithm;
		private int _blockSize;
		
		public HMACGeneric(byte[] key, string hashName, int blockSize)
		{
			if (key == null)
				throw new ArgumentNullException("key");
			
			_hashAlgorithm = HashAlgorithm.Create(hashName);
			_blockSize = blockSize;
			
			if (key.Length > blockSize) {
				KeyValue = _hashAlgorithm.ComputeHash(key);
			} else {
				KeyValue = (byte[]) key.Clone();
			}
			HashSizeValue = _hashAlgorithm.HashSize;
		}
		
		public override void Initialize()
		{
			byte[] padding = new byte[_blockSize];
			Buffer.BlockCopy(KeyValue, 0, padding, 0, KeyValue.Length);
			for (int i=0; i<padding.Length; i++) {
				padding[i] ^= 0x36;
			}
			
			_hashAlgorithm.Initialize();
			_hashAlgorithm.TransformBlock(padding, 0, padding.Length, padding, 0);
		}
		
		protected override void HashCore(byte[] rgb, int ib, int cb)
		{
			_hashAlgorithm.TransformBlock(rgb, ib, cb, rgb, ib);
		}
		
		protected override byte[] HashFinal()
		{
			byte[] padding = new byte[_blockSize];
			Buffer.BlockCopy(KeyValue, 0, padding, 0, KeyValue.Length);
			for (int i=0; i<padding.Length; i++) {
				padding[i] ^= 0x5C;
			}
			
			// Finish the inner hash
			_hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);
			byte[] innerHash = _hashAlgorithm.Hash;
			
			// Finish the outer hash
			_hashAlgorithm.Initialize();
			_hashAlgorithm.TransformBlock(padding, 0, padding.Length, padding, 0);
			_hashAlgorithm.TransformFinalBlock(innerHash, 0, innerHash.Length);
			byte[] outerHash = _hashAlgorithm.Hash;
			
			return outerHash;
		}
	}
	
	internal sealed class TLSGenericDeriveBytes : DeriveBytes
	{
		private KeyedHashAlgorithm _hmac;
		private byte[] _seed;

		private byte[] _Ai;
		private byte[] _Hash;

		public TLSGenericDeriveBytes(TLSGenericType type, byte[] secret, byte[] seed)
		{
			/* Here should be all supported types */
			switch (type) {
			case TLSGenericType.MD5:
				_hmac = new HMACGeneric(secret, "MD5", 64);
				break;
			case TLSGenericType.SHA1:
				_hmac = new HMACGeneric(secret, "SHA1", 64);
				break;
			case TLSGenericType.SHA256:
				_hmac = new HMACGeneric(secret, "SHA256", 64);
				break;
			case TLSGenericType.SHA384:
				_hmac = new HMACGeneric(secret, "SHA384", 128);
				break;
			case TLSGenericType.SHA512:
				_hmac = new HMACGeneric(secret, "SHA512", 128);
				break;
			default:
				throw new Exception("Unsupported TLSGenericType");
			}

			/* Set the seed as our parameter */
			_seed = seed;

			/* Reset the HMAC generators */
			Reset();
		}

		public override void Reset() {
			_Ai = _seed;
			_Hash = new byte[0];
		}

		public override byte[] GetBytes(int count) {
			byte[] ret = new byte[count];

			int filled = 0;
			while (filled < count) {
				if (filled + _Hash.Length < count) {
					/* Copy current hash into results */
					Array.Copy(_Hash, 0, ret, filled, _Hash.Length);
					filled += _Hash.Length;

					_hmac.Initialize();
					_Ai = _hmac.ComputeHash(_Ai);

					/* Calculate the next hash */
					_hmac.Initialize();
					_hmac.TransformBlock(_Ai, 0, _Ai.Length, _Ai, 0);
					_hmac.TransformFinalBlock(_seed, 0, _seed.Length);
					_Hash = _hmac.Hash;
				} else {
					/* Count how many bytes to consume */
					int consumed = count - filled;

					/* Make a partial copy of the current hash */
					Array.Copy(_Hash, 0, ret, filled, consumed);
					filled += consumed;

					/* Remove read bytes from the current hash */
					byte[] tmp = new byte[_Hash.Length - consumed];
					Array.Copy(_Hash, consumed, tmp, 0, tmp.Length);
					_Hash = tmp;
				}
			}
			
			return ret;
		}
	}

	public class PseudoRandomFunctionTLSGeneric : PseudoRandomFunction
	{
		private TLSGenericType _type;

		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return version.HasSelectablePRF;
		}
		
		public PseudoRandomFunctionTLSGeneric(string type)
		{
			if (type.Equals("MD5")) {
				_type = TLSGenericType.MD5;
			} else if (type.Equals("SHA1")) {
				_type = TLSGenericType.SHA1;
			} else if (type.Equals("SHA256")) {
				_type = TLSGenericType.SHA256;
			} else if (type.Equals("SHA384")) {
				_type = TLSGenericType.SHA384;
			} else if (type.Equals("SHA512")) {
				_type = TLSGenericType.SHA512;
			} else {
				throw new Exception("Unsupported PRF type");
			}
		}

		public override HashAlgorithm CreateVerifyHashAlgorithm(byte[] secret)
		{
			switch (_type) {
			case TLSGenericType.MD5:
				return new MD5CryptoServiceProvider();
			case TLSGenericType.SHA1:
				return new SHA1CryptoServiceProvider();
			case TLSGenericType.SHA256:
				return new SHA256Managed();
			case TLSGenericType.SHA384:
				return new SHA384Managed();
			case TLSGenericType.SHA512:
				return new SHA512Managed();
			default:
				throw new Exception("Unsupported TLSGenericType");
			}
		}
		
		public override int VerifyDataLength
		{
			get { return 12; }
		}

		public override DeriveBytes CreateDeriveBytes(byte[] secret, byte[] seed)
		{
			return new TLSGenericDeriveBytes(_type, secret, seed);
		}
	}
}
