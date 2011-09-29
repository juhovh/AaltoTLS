//
// KeyExchangeAlgorithmECDHE
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

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;

namespace BouncyCastleCipherSuitePlugin
{
	public class KeyExchangeAlgorithmECDHE : KeyExchangeAlgorithm
	{
		private ECDomainParameters _domainParameters;
		private ECPrivateKeyParameters _privateKey;
		private ECPublicKeyParameters _publicKey;
		
		private byte[] _preMasterSecret;
		
		public override string CertificateKeyAlgorithm
		{
			get { return null; }
		}
		
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}
		
		private void GenerateKeys(string curveName)
		{
			X9ECParameters ecParams = SecNamedCurves.GetByName(curveName);
			_domainParameters = new ECDomainParameters(ecParams.Curve,
			                                           ecParams.G, ecParams.N, ecParams.H,
			                                           ecParams.GetSeed());
			ECKeyGenerationParameters keyGenParams =
				new ECKeyGenerationParameters(_domainParameters, new SecureRandom());
			
			AsymmetricCipherKeyPair keyPair;
			ECKeyPairGenerator generator = new ECKeyPairGenerator();
			generator.Init(keyGenParams);
			keyPair = generator.GenerateKeyPair();
			
			_privateKey = (ECPrivateKeyParameters) keyPair.Private;
			_publicKey = (ECPublicKeyParameters) keyPair.Public;
		}
		
		public override byte[] GetServerKeys(ProtocolVersion version)
		{
			GenerateKeys("secp256r1");
			
			byte[] publicKey = _publicKey.Q.GetEncoded();
			byte[] serverKeys = new byte[4+publicKey.Length];
			serverKeys[0] = 3;
			serverKeys[2] = 23; // Should match curve type
			serverKeys[3] = (byte) publicKey.Length;
			Buffer.BlockCopy(publicKey, 0, serverKeys, 3, publicKey.Length);
			
			return serverKeys;
		}
		
		public override byte[] ProcessServerKeys(ProtocolVersion version, byte[] data)
		{
			if (data == null)
				throw new ArgumentNullException("data");
			if (data.Length < 4)
				throw new ArgumentException("data");
			
			if (data[0] != 3 || data[1] != 0 || data[2] != 23)
				throw new ArgumentException("data");
			if (data[3] != 65 || data[4] > data.Length-4)
				throw new ArgumentException("data");
			
			// Generate our private key
			GenerateKeys("secp256r1");
			
			// Extract the public key from the data
			byte[] ecPointData = new byte[data[3]];
			Buffer.BlockCopy(data, 4, ecPointData, 0, ecPointData.Length);
			ECPoint ecPoint = _domainParameters.Curve.DecodePoint(ecPointData);
			ECPublicKeyParameters theirPublicKey = new ECPublicKeyParameters(ecPoint, _domainParameters);
			
			// Calculate the actual agreement
			ECDHBasicAgreement agreement = new ECDHBasicAgreement();
			agreement.Init(_privateKey);
			_preMasterSecret = BigIntegerToByteArray(agreement.CalculateAgreement(theirPublicKey), 32);
			
			byte[] signature = new byte[data.Length-4-data[3]];
			Buffer.BlockCopy(data, 4+data[3], signature, 0, signature.Length);
			return signature;
		}
		
		public override byte[] GetClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePublicKey publicKey)
		{
			byte[] ecPoint = _publicKey.Q.GetEncoded();
			
			byte[] ret = new byte[1+ecPoint.Length];
			ret[0] = (byte) (ecPoint.Length);
			Buffer.BlockCopy(ecPoint, 0, ret, 1, ecPoint.Length);
			return ret;
		}
		
		public override void ProcessClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePrivateKey privateKey, byte[] data)
		{
			if (data == null)
				throw new ArgumentNullException("data");
			if (data.Length < 1)
				throw new ArgumentException("data");
			
			byte[] ecPointData = new byte[data[0]];
			Buffer.BlockCopy(data, 1, ecPointData, 0, ecPointData.Length);
			ECPoint ecPoint = _domainParameters.Curve.DecodePoint(ecPointData);
			ECPublicKeyParameters theirPublicKey = new ECPublicKeyParameters(ecPoint, _domainParameters);
			
			// Calculate the actual agreement
			ECDHBasicAgreement agreement = new ECDHBasicAgreement();
			agreement.Init(_privateKey);
			_preMasterSecret = BigIntegerToByteArray(agreement.CalculateAgreement(theirPublicKey), 32);
		}
		
		public override byte[] GetMasterSecret(PseudoRandomFunction prf, byte[] seed)
		{
			return prf.CreateDeriveBytes(_preMasterSecret, "master secret", seed).GetBytes(48);
		}
		
		
		
		
		private static byte[] BigIntegerToByteArray(BigInteger input, int length)
		{
			byte[] result = new byte[length];
			byte[] inputBytes = input.ToByteArray();
			Array.Reverse(inputBytes);
			Buffer.BlockCopy(inputBytes, 0, result, 0, System.Math.Min(inputBytes.Length, result.Length));
			Array.Reverse(result);
			return result;
		}
	}
}
