//
// KeyExchangeAlgorithmDHE
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
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AaltoTLS.PluginInterface;

namespace BigIntegerCipherSuitePlugin
{
	public class KeyExchangeAlgorithmDHE : KeyExchangeAlgorithm
	{
		private int _pLength;
		
		// These parameters are big-endian (network byte order)
		private byte[] _dh_p  = new byte[0];
		private byte[] _dh_g  = new byte[0];
		private byte[] _dh_x  = new byte[0];
		private byte[] _dh_Ys = new byte[0];
		private byte[] _dh_Yc = new byte[0];
		private byte[] _preMasterSecret = null;
		
		public override string CertificateKeyAlgorithm
		{
			get { return null; }
		}
		
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}

		public override byte[] GetServerKeys(ProtocolVersion version)
		{
			// Set default length for P;
			_pLength = 1024/8;
			
			// Generate P, G and X
			BigInteger p, g;
			GenerateKey(_pLength*8, out p, out g);
			BigInteger x = GenerateX(p);

			// Calculate the server parameter
			BigInteger Ys = BigInteger.ModPow(g, x, p);

			// Store all values to the byte arrays
			_dh_p = BigIntegerToByteArray(p, _pLength);
			_dh_g = BigIntegerToByteArray(g, 1); // Single byte
			_dh_x = BigIntegerToByteArray(x, _pLength);
			_dh_Ys = BigIntegerToByteArray(Ys, _pLength);

			int idx = 0;
			byte[] data = new byte[2+_dh_p.Length + 2+_dh_g.Length + 2+_dh_Ys.Length];

			data[idx++] = (byte) (_dh_p.Length >> 8);
			data[idx++] = (byte) (_dh_p.Length);
			Array.Copy(_dh_p, 0, data, idx, _dh_p.Length);
			idx += _dh_p.Length;

			data[idx++] = (byte) (_dh_g.Length >> 8);
			data[idx++] = (byte) (_dh_g.Length);
			Array.Copy(_dh_g, 0, data, idx, _dh_g.Length);
			idx += _dh_g.Length;

			data[idx++] = (byte) (_dh_Ys.Length >> 8);
			data[idx++] = (byte) (_dh_Ys.Length);
			Array.Copy(_dh_Ys, 0, data, idx, _dh_Ys.Length);
			idx += _dh_Ys.Length;

			return data;
		}

		public override byte[] ProcessServerKeys(ProtocolVersion version, byte[] data)
		{
			int pos = 0;

			int pLen = (data[pos] << 8) | data[pos+1];
			pos += 2+pLen;
			int gLen = (data[pos] << 8) | data[pos+1];
			pos += 2+gLen;
			int YsLen = (data[pos] << 8) | data[pos+1];
			pos += 2+YsLen;
			if (pos > data.Length) {
				throw new Exception("Not enough data in server keys");
			}

			_pLength = pLen;
			_dh_p = new byte[pLen];
			_dh_g = new byte[gLen];
			_dh_Ys = new byte[YsLen];

			Buffer.BlockCopy(data, 2, _dh_p, 0, pLen);
			Buffer.BlockCopy(data, 4+pLen, _dh_g, 0, gLen);
			Buffer.BlockCopy(data, 6+pLen+gLen, _dh_Ys, 0, YsLen);

			byte[] signature = new byte[data.Length-pos];
			Buffer.BlockCopy(data, pos, signature, 0, signature.Length);
			return signature;
		}
		
		public override byte[] GetClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePublicKey publicKey)
		{
			if (_dh_p.Length == 0 || _dh_g.Length == 0 || _dh_Ys.Length == 0)
				throw new Exception("Server keys not generated/received");
			
			// Create corresponding BigIntegers
			BigInteger p = ByteArrayToBigInteger(_dh_p);
			BigInteger g = ByteArrayToBigInteger(_dh_g);
			BigInteger Ys = ByteArrayToBigInteger(_dh_Ys);

			// Generate new private value X between 0 and P-1
			BigInteger x = GenerateX(p);

			// Calculate pre-master secret
			BigInteger Z = BigInteger.ModPow(Ys, x, p);
			_preMasterSecret = BigIntegerToByteArray(Z, _pLength);

			// Calculate the client parameter
			BigInteger Yc = BigInteger.ModPow(g, x, p);
			_dh_Yc = BigIntegerToByteArray(Yc, _pLength);

			// Return the client parameter that will be sent
			byte[] ret = new byte[2+_dh_Yc.Length];
			ret[0] = (byte) (_dh_Yc.Length >> 8);
			ret[1] = (byte) (_dh_Yc.Length);
			Buffer.BlockCopy(_dh_Yc, 0, ret, 2, _dh_Yc.Length);
			return ret;
		}
		
		public override void ProcessClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePrivateKey privateKey, byte[] data)
		{
			if (_dh_p.Length == 0 || _dh_g.Length == 0 || _dh_Ys.Length == 0)
				throw new Exception("Server keys not generated/received");
			if (((data[0] << 8) | data[1]) != data.Length-2)
				throw new Exception("Client key exchange vector length incorrect");

			// Store the client parameter
			byte[] _dh_Yc = new byte[data.Length-2];
			Buffer.BlockCopy(data, 2, _dh_Yc, 0, data.Length-2);

			// Create corresponding BigIntegers
			BigInteger p = ByteArrayToBigInteger(_dh_p);
			BigInteger x = ByteArrayToBigInteger(_dh_x);
			BigInteger Yc = ByteArrayToBigInteger(_dh_Yc);

			// Calculate pre-master secret
			BigInteger Z = BigInteger.ModPow(Yc, x, p);
			_preMasterSecret = BigIntegerToByteArray(Z, _pLength);
		}

		public override byte[] GetMasterSecret(PseudoRandomFunction prf, byte[] seed)
		{
			return prf.CreateDeriveBytes(_preMasterSecret, "master secret", seed).GetBytes(48);
		}
		
		private static BigInteger ByteArrayToBigInteger(byte[] input)
		{
			byte[] tmp = new byte[input.Length+1];
			Buffer.BlockCopy(input, 0, tmp, 1, input.Length);
			Array.Reverse(tmp);
			return new BigInteger(tmp);
		}
		
		private static byte[] BigIntegerToByteArray(BigInteger input, int length)
		{
			byte[] result = new byte[length];
			byte[] inputBytes = input.ToByteArray();
			Buffer.BlockCopy(inputBytes, 0, result, 0, System.Math.Min(inputBytes.Length, result.Length));
			Array.Reverse(result);
			return result;
		}
		
		private static BigInteger GenerateX(BigInteger p)
		{
			RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
			byte[] xBytes = new byte[p.ToByteArray().Length+1];
			
			BigInteger x = new BigInteger();
			while ((x == 0) || (x >= p)) {
				rngCsp.GetBytes(xBytes);
				xBytes[xBytes.Length-1] = 0x00;
				x = new BigInteger(xBytes);
			}
			return x;
		}
		
		// Currently uses OAKLEY primes, for more information see RFC 2412 APPENDIX E
		private static void GenerateKey(int bitLength, out BigInteger p, out BigInteger g)
		{
			if (bitLength == 768) {
				p = ByteArrayToBigInteger(OAKLEY768P);
			} else if (bitLength == 1024) {
				p = ByteArrayToBigInteger(OAKLEY1024P);
			} else if (bitLength == 1536) {
				p = ByteArrayToBigInteger(OAKLEY1536P);
			} else {
				throw new Exception("Bit length of " + bitLength + " not supported in DH key");
			}
			// Same generator in all OAKLEY primes
			g = ByteArrayToBigInteger(new byte[] { 0x22 });
		}
		
		private static readonly byte[] OAKLEY768P = new byte[] {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
		};
		
		private static readonly byte[] OAKLEY1024P = new byte[] {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
		};
		
		private static readonly byte[] OAKLEY1536P = new byte[] {
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
			0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
			0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
			0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
			0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
			0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
			0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
			0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
			0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
			0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
			0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
			0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
			0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
			0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
			0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
		};
	}
}
