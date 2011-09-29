//
// SignatureAlgorithmDSA
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
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AaltoTLS.PluginInterface;

namespace BaseCipherSuitePlugin
{
	public class SignatureAlgorithmDSA : SignatureAlgorithm
	{
		public override string CertificateKeyAlgorithm
		{
			 get { return "1.2.840.10040.4.1"; }
		}

		public override byte SignatureAlgorithmType
		{
			// SignatureAlgorithm.dsa
			get { return 2; }
		}

		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}

		public override bool SupportsHashAlgorithmType(byte hashAlgorithm)
		{
			// Only HashAlgorithm.sha1 supported
			if (hashAlgorithm == 2) {
				return true;
			}

			return false;
		}

		public override CertificatePrivateKey ImportPrivateKey(byte[] keyData)
		{
			try {
				string keyString = Encoding.ASCII.GetString(keyData).Trim();
				if (keyString.StartsWith("<DSAKeyValue>")) {
					DSACryptoServiceProvider dsa = new DSACryptoServiceProvider();
					dsa.FromXmlString(keyString);
					return new CertificatePrivateKey(CertificateKeyAlgorithm, dsa);
				}
			} catch (Exception) {}
			
			return null;
		}
		
		public override byte[] SignData(ProtocolVersion version, byte[] data, HashAlgorithm hashAlgorithm, CertificatePrivateKey privateKey)
		{
			if (hashAlgorithm != null && !(hashAlgorithm is SHA1)) {
				throw new Exception("DSA signature requires SHA1 hash algorithm");
			}
			if (!(privateKey.Algorithm is DSACryptoServiceProvider)) {
				throw new Exception("DSA signature requires DSA private key");
			}

			DSACryptoServiceProvider dsaKey = (DSACryptoServiceProvider) privateKey.Algorithm;
			if (dsaKey.PublicOnly) {
				throw new Exception("DSA private key required for signing");
			}

			return DEREncodeSignature(dsaKey.SignData(data));
		}

		public override bool VerifyData(ProtocolVersion version, byte[] data, HashAlgorithm hashAlgorithm, CertificatePublicKey publicKey, byte[] signature)
		{
			if (hashAlgorithm != null && !(hashAlgorithm is SHA1)) {
				throw new Exception("DSA signature verification requires SHA1 hash algorithm");
			}
			if (!CertificateKeyAlgorithm.Equals(publicKey.Oid) || !(publicKey.Algorithm is DSACryptoServiceProvider)) {
				throw new Exception("DSA signature verification requires DSA public key");
			}
			
			return VerifyData(data, (DSACryptoServiceProvider)publicKey.Algorithm, signature);
		}
		
		public bool VerifyData(byte[] buffer, DSACryptoServiceProvider dsaKey, byte[] signature)
		{
			return dsaKey.VerifyData(buffer, DERDecodeSignature(signature));
		}
		
		
		private static byte[] DEREncodeSignature(byte[] signature)
		{
			// This is the largest we can encode, adds 8 more bytes
			if (signature.Length > 65526 || (signature.Length%2) != 0) {
				throw new Exception("Invalid signature length");
			}
			
			int vectorLength = (signature.Length/2 < 128) ? 2+(signature.Length/2) :
			                   (signature.Length/2 < 256) ? 3+(signature.Length/2) :
			                   4+(signature.Length/2);
			
			byte[] encoded = new byte[2*vectorLength];
			encoded[0] = 0x02;
			DEREncodeVector(signature, 0, signature.Length/2, encoded, 1);
			encoded[vectorLength] = 0x02;
			DEREncodeVector(signature, signature.Length/2, signature.Length/2, encoded, vectorLength+1);
			
			int retLength = (encoded.Length < 128) ? 2+encoded.Length :
			                (encoded.Length < 256) ? 3+encoded.Length :
			                4+encoded.Length;
			
			byte[] ret = new byte[retLength];
			ret[0] = 0x30;
			DEREncodeVector(encoded, 0, encoded.Length, ret, 1);
			return ret;
		}
		
		private static byte[] DERDecodeSignature(byte[] data)
		{
			// In DSA the signature length is always 2*20 bytes
			int sigLength = 20;
			
			// This is the largest we can decode, check type
			if (data.Length > 65538 || data[0] != 0x30) {
				throw new Exception("Invalid signature");
			}
			
			int fullConsumed;
			byte[] encoded = DERDecodeVector(data, 1, out fullConsumed);
			if (encoded[0] != 0x02)
				throw new Exception("Invalid signature");
			
			int rConsumed;
			byte[] R = DERDecodeVector(encoded, 1, out rConsumed);
			if (encoded[1+rConsumed] != 0x02)
				throw new Exception("Invalid signature");
			
			int sConsumed;
			byte[] S = DERDecodeVector(encoded, 1+rConsumed+1, out sConsumed);
			if (1+rConsumed+1+sConsumed != encoded.Length)
				throw new Exception("Invalid signature");
			
			// Make sure the signature is valid
			for (int i=0; i<R.Length-sigLength; i++) {
				if (R[i] != 0)
					throw new Exception("Invalid signature");
			}
			for (int i=0; i<S.Length-sigLength; i++) {
				if (S[i] != 0)
					throw new Exception("Invalid signature");
			}
			
			// Copy signature bytes to the decoded array
			byte[] ret = new byte[sigLength*2];
			Buffer.BlockCopy(R, System.Math.Max(0, R.Length-sigLength),
			                 ret, System.Math.Max(0, sigLength-R.Length),
			                 System.Math.Min(sigLength, R.Length));
			Buffer.BlockCopy(S, System.Math.Max(0, S.Length-sigLength),
			                 ret, sigLength+System.Math.Max(0, sigLength-S.Length),
			                 System.Math.Min(sigLength, S.Length));
			return ret;
		}
		
		private static void DEREncodeVector(byte[] vector, int idx1, int length, byte[] output, int idx2)
		{
			if (length < 128) {
				output[idx2++] = (byte) length;
			} else if (length < 256) {
				output[idx2++] = 0x81;
				output[idx2++] = (byte) length;
			} else {
				output[idx2++] = 0x82;
				output[idx2++] = (byte) (length >> 8);
				output[idx2++] = (byte) (length);
			}
			Buffer.BlockCopy(vector, idx1, output, idx2, length);
		}
		
		private static byte[] DERDecodeVector(byte[] input, int idx, out int consumed)
		{
			int length;
			if (input[idx] < 128) {
				length = input[idx];
				consumed = 1+length;
				idx += 1;
			} else if (input[idx] == 0x81) {
				length = input[idx+1];
				consumed = 2+length;
				idx += 2;
			} else if (input[idx] == 0x82) {
				length = (input[idx+1] << 8) | input[idx+2];
				consumed = 3+length;
				idx += 3;
			} else {
				throw new Exception("Unsupported DER vector length");
			}
			
			byte[] ret = new byte[length];
			Buffer.BlockCopy(input, idx, ret, 0, ret.Length);
			return ret;
		}
	}
}
