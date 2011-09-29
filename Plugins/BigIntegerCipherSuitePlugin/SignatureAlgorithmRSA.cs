//
// SignatureAlgorithmRSA
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
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AaltoTLS.PluginInterface;

namespace BigIntegerCipherSuitePlugin
{
	public class SignatureAlgorithmRSA : SignatureAlgorithm
	{
		public override string CertificateKeyAlgorithm
		{
			 get { return "1.2.840.113549.1.1.1"; }
		}

		public override byte SignatureAlgorithmType
		{
			// SignatureAlgorithm.rsa
			get { return 1; }
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
			try {
				string keyString = Encoding.ASCII.GetString(keyData).Trim();
				if (keyString.StartsWith("<RSAKeyValue>")) {
					RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
					rsa.FromXmlString(keyString);
					return new CertificatePrivateKey(CertificateKeyAlgorithm, rsa);
				}
			} catch (Exception) {}
			
			return null;
		}

		public override byte[] SignData(ProtocolVersion version, byte[] data, HashAlgorithm hashAlgorithm, CertificatePrivateKey privateKey)
		{
			if (!(privateKey.Algorithm is RSACryptoServiceProvider)) {
				throw new Exception("RSA signature requires RSA private key");
			}

			RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider) privateKey.Algorithm;
			if (rsaKey.PublicOnly) {
				throw new Exception("RSA private key required for signing");
			}
			
			if (hashAlgorithm == null) {
				// Before TLS 1.2 RSA signatures always used MD5+SHA1
				// MD5+SHA1 is not supported by .NET, so we need custom code
				return TLSv1SignData(rsaKey, data);
			} else {
				// Starting from TLS 1.2 the standard signature is used
				return rsaKey.SignData(data, hashAlgorithm);
			}
		}

		public override bool VerifyData(ProtocolVersion version, byte[] data, HashAlgorithm hashAlgorithm, CertificatePublicKey publicKey, byte[] signature)
		{
			if (!CertificateKeyAlgorithm.Equals(publicKey.Oid)) {
				throw new Exception("RSA signature verification requires RSA public key");
			}

			RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider) publicKey.Algorithm;
			if (hashAlgorithm == null) {
				// Before TLS 1.2 RSA signatures always used MD5+SHA1
				// MD5+SHA1 is not supported by .NET, so we need custom code
				return TLSv1VerifyData(rsaKey, data, signature);
			} else {
				// Starting from TLS 1.2 the standard signature is used
				return rsaKey.VerifyData(data, hashAlgorithm, signature);
			}
		}

		private static byte[] TLSv1SignData(RSACryptoServiceProvider rsaKey, byte[] buffer)
		{
			int keySize = (rsaKey.KeySize/8);

			// Hash input data and PKCS #1.5 encode the resulting hash
			byte[] hash = EncodeSignatureHash(TLSv1HashData(buffer), keySize);

			// Export private key parameters and encrypt hash manually using BigInteger
			RSAParameters parameters = rsaKey.ExportParameters(true);
			BigInteger c = new BigInteger(OS2IP(hash));
			BigInteger d = new BigInteger(OS2IP(parameters.D));
			BigInteger n = new BigInteger(OS2IP(parameters.Modulus));
			BigInteger m = BigInteger.ModPow(c, d, n);

			// Convert the resulting integer into signature bytes
			return I2OSP(m.ToByteArray(), keySize);
		}

		private static bool TLSv1VerifyData(RSACryptoServiceProvider rsaKey, byte[] buffer, byte[] signature)
		{
			int keySize = (rsaKey.KeySize/8);

			// Hash input data and PKCS #1.5 encode the resulting hash
			byte[] ourHash = EncodeSignatureHash(TLSv1HashData(buffer), keySize);

			// Export public key parameters and decrypt signature manually using BigInteger
			RSAParameters parameters = rsaKey.ExportParameters(false);
			BigInteger s = new BigInteger(OS2IP(signature));
			BigInteger e = new BigInteger(OS2IP(parameters.Exponent));
			BigInteger n = new BigInteger(OS2IP(parameters.Modulus));
			BigInteger m = BigInteger.ModPow(s, e, n);

			 // Convert the resulting integer into signature bytes
			byte[] theirHash = I2OSP(m.ToByteArray(), keySize);

			// Verify that both hashes match, which means signature is valid
			bool verifyOk = false;
			if (theirHash.Length == ourHash.Length) {
				verifyOk = true;
				for (int i=0; i<ourHash.Length; i++) {
					if (theirHash[i] != ourHash[i]) {
						verifyOk = false;
					}
				}
			}
			return verifyOk;
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


		// RFC 3447 Section 9.2 without digestAlgorithm info
		private static byte[] EncodeSignatureHash(byte[] hash, int length)
		{
			int padLength = length - hash.Length - 3;
			if (padLength < 8) {
				throw new Exception("Too large hash value to encode");
			}

			// EM(message) = 0x00 || 0x01 || PS(pad) || 0x00 || T(hash)
			byte[] message = new byte[length];
			message[1] = 0x01;
			for (int i=0; i<padLength; i++) {
				message[2+i] = 0xff;
			}
			Buffer.BlockCopy(hash, 0, message, 3+padLength, hash.Length);
			return message;
		}

		// RFC 3447 Section 4.1, simply add null bytes and reverse
		public static byte[] I2OSP (byte[] x, int xLen)
		{
			byte[] result = new byte[xLen];
			if ((x.Length == xLen+1) && (x[x.Length-1] == 0)) {
				Buffer.BlockCopy(x, 0, result, 0, xLen);
			} else {
				Buffer.BlockCopy(x, 0, result, 0, x.Length);
			}
			Array.Reverse(result);

			return result;
		}

		// RFC 3447 Section 4.2, add null byte to make sure it's signed and reverse
		public static byte[] OS2IP (byte[] x)
		{
			byte[] result = new byte[1 + x.Length];
			Buffer.BlockCopy(x, 0, result, 1, x.Length);
			Array.Reverse(result);

			return result;
		}
	}
}
