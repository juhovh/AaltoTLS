//
// KeyExchangeAlgorithmRSA
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
using AaltoTLS.PluginInterface;

namespace BaseCipherSuitePlugin
{
	public class KeyExchangeAlgorithmRSA : KeyExchangeAlgorithm
	{
		private byte[] _preMasterSecret = null;
		
		public override string CertificateKeyAlgorithm
		{
			get { return "1.2.840.113549.1.1.1"; }
		}
		
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}

		public override byte[] GetServerKeys(ProtocolVersion version)
		{
			// No server keys sent in RSA key exchange
			return null;
		}

		public override byte[] ProcessServerKeys(ProtocolVersion version, byte[] data)
		{
			throw new CryptographicException("RSA key exchange received server keys");
		}

		public override byte[] GetClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePublicKey publicKey)
		{
			if (!(publicKey.Algorithm is RSACryptoServiceProvider)) {
				throw new CryptographicException("RSA key exchange requires RSA public key");
			}
			return GetClientKeys(version, clientVersion, (RSACryptoServiceProvider)publicKey.Algorithm);
		}
		
		public byte[] GetClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, RSACryptoServiceProvider rsa)
		{
			_preMasterSecret = new byte[48];

			RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
			rngCsp.GetBytes(_preMasterSecret);

			_preMasterSecret[0] = clientVersion.Major;
			_preMasterSecret[1] = clientVersion.Minor;

			byte[] encryptedBytes = rsa.Encrypt(_preMasterSecret, false);
			
			byte[] ret;
			if (version != ProtocolVersion.SSL3_0) {
				// TLS 1.0 and later require a useless vector length
				ret = new byte[2+encryptedBytes.Length];
				ret[0] = (byte) (encryptedBytes.Length >> 8);
				ret[1] = (byte) (encryptedBytes.Length);
				Buffer.BlockCopy(encryptedBytes, 0, ret, 2, encryptedBytes.Length);
			} else {
				ret = encryptedBytes;
			}
			return ret;
		}
		
		public override void ProcessClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePrivateKey privateKey, byte[] data)
		{
			if (!(privateKey.Algorithm is RSACryptoServiceProvider)) {
				throw new CryptographicException("RSA key exchange requires RSA private key");
			}
			RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)privateKey.Algorithm;
			
			try {
				// TLS 1.0 and later require a useless vector length
				if (version != ProtocolVersion.SSL3_0) {
					if (((data[0] << 8) | data[1]) != data.Length-2) {
						throw new Exception("Client key exchange vector length incorrect");
					}

					// Remove vector length from the data bytes
					byte[] tmpArray = new byte[data.Length-2];
					Buffer.BlockCopy(data, 2, tmpArray, 0, tmpArray.Length);
					data = tmpArray;
				}
			
				data = rsa.Decrypt(data, false);
				if (data.Length != 48) {
					throw new Exception("Invalid premaster secret length");
				}
				if (data[0] != clientVersion.Major || data[1] != clientVersion.Minor) {
					throw new Exception("RSA client key version mismatch");
				}
				_preMasterSecret = data;
			} catch (Exception) {
				// Randomize the pre-master secret in case of an error
				RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
				_preMasterSecret = new byte[48];
				rngCsp.GetBytes(_preMasterSecret);
			}
		}

		public override byte[] GetMasterSecret(PseudoRandomFunction prf, byte[] seed)
		{
			if (_preMasterSecret == null)
				throw new CryptographicException("Premaster secret not defined");
			
			return prf.CreateDeriveBytes(_preMasterSecret, "master secret", seed).GetBytes(48);
		}
	}
}
