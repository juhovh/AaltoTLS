//
// SignatureAlgorithmECDSA
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

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Parameters;

namespace BouncyCastleCipherSuitePlugin
{
	public class SignatureAlgorithmECDSA : SignatureAlgorithm
	{
		/*
		private readonly string P256OID = "1.2.840.10045.3.1.7";
		private readonly string P384OID = "1.3.132.0.34";
		private readonly string P521OID = "1.3.132.0.35";
		*/
		
		public override string CertificateKeyAlgorithm
		{
			 get { return "1.2.840.10045.2.1"; }
		}

		public override byte SignatureAlgorithmType
		{
			// SignatureAlgorithm.ecdsa
			get { return 3; }
		}

		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}
		
		public override bool SupportsHashAlgorithmType(byte hashAlgorithm)
		{
			// Known HashAlgorithms listed here
			switch (hashAlgorithm) {
			case 1: // HashAlgorithm.md5
			case 2: // HashAlgorithm.sha1
			case 4: // HashAlgorithm.sha256
			case 5: // HashAlgorithm.sha384
			case 6: // HashAlgorithm.sha512
				return true;
			default:
				return false;
			}
		}
		
		public override CertificatePrivateKey ImportPrivateKey(byte[] keyData)
		{
			return null;
		}
		
		public override byte[] SignData(ProtocolVersion version, byte[] data, HashAlgorithm hashAlgorithm, CertificatePrivateKey privateKey)
		{
			return new byte[0];
		}
		
		public override bool VerifyData(ProtocolVersion version, byte[] data, HashAlgorithm hashAlgorithm, CertificatePublicKey publicKey, byte[] signature)
		{
			if (!CertificateKeyAlgorithm.Equals(publicKey.Oid)) {
				throw new Exception("ECDSA signature verification requires ECDSA public key");
			}
			
			// Decode the public key parameters
			string curveOid = DER2OID(publicKey.Parameters);
			if (curveOid == null) {
				throw new Exception("Unsupported ECDSA public key parameters");
			}
			
			// Get parameters from the curve OID
			X9ECParameters ecParams = SecNamedCurves.GetByOid(new DerObjectIdentifier(curveOid));
			if (ecParams == null) {
				throw new Exception("Unsupported ECC curve type OID: " + curveOid);
			}
			
			// Construct domain parameters
			ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve,
			                                                             ecParams.G, ecParams.N, ecParams.H,
			                                                             ecParams.GetSeed());
			
			// Decode the public key data
			byte[] ecPointData = publicKey.KeyValue;
			if (ecPointData[0] != 0x04) {
				throw new Exception("Only uncompressed ECDSA keys supported, format: " + ecPointData[0]);
			}
			ECPoint ecPoint = domainParameters.Curve.DecodePoint(ecPointData);
			ECPublicKeyParameters theirPublicKey = new ECPublicKeyParameters(ecPoint, domainParameters);
			
			// Hash input data buffer
			byte[] dataHash;
			if (hashAlgorithm == null) {
				dataHash = TLSv1HashData(data);
			} else {
				dataHash = hashAlgorithm.ComputeHash(data);
			}
			
			// Actually verify the signature
			BigInteger[] sig = DERDecodeSignature(signature);
			ECDsaSigner signer = new ECDsaSigner();
			signer.Init(false, theirPublicKey);
			return signer.VerifySignature(dataHash, sig[0], sig[1]);
		}
		
		// SSL 3.0, TLS 1.0 and TLS 1.1 all use MD5+SHA1 for signature
		private static byte[] TLSv1HashData(byte[] buffer)
		{
			MD5 md5 = new MD5CryptoServiceProvider();
			byte[] md5Hash = md5.ComputeHash(buffer);

			SHA1 sha1 = new SHA1CryptoServiceProvider();
			byte[] sha1Hash = sha1.ComputeHash(buffer);

			byte[] hash = new byte[md5Hash.Length + sha1Hash.Length];
			Buffer.BlockCopy(md5Hash, 0, hash, 0, md5Hash.Length);
			Buffer.BlockCopy(sha1Hash, 0, hash, md5Hash.Length, sha1Hash.Length);
			return hash;
		}
		
		private static string DER2OID(byte[] oid)
		{
			try {
				if (oid[0] != 0x06 || oid[1] >= 128 || oid[1] != oid.Length-2) {
					return null;
				}
				
				byte firstByte = oid[2];
				string ret = (firstByte / 40) + "." + (firstByte % 40) + ".";
				for (int i=3; i<oid.Length; i++) {
					if (oid[i] < 128) {
						ret += (int) oid[i];
					} else if (oid[i] >= 128 && oid[i+1] < 128) {
						ret += (int) (((oid[i] & 0x7f) << 7) | oid[i+1]);
						i++;
					} else {
						return null;
					}
					
					if (i != oid.Length-1) {
						ret += ".";
					}
				}
				return ret;
			} catch (Exception) {
				return null;
			}
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
		
		private static BigInteger[] DERDecodeSignature(byte[] data)
		{
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
			
			// Return an array containing both R and S
			return new BigInteger[] { new BigInteger(R), new BigInteger(S) };
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
