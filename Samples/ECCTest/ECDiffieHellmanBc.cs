using System;
using System.Text;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Parameters;

namespace ECCTest
{
	public class ECDiffieHellmanBc
	{
		private Int32                    _keySize;
		private ECDomainParameters       _domainParameters;
		private ECPrivateKeyParameters   _privateKeyParameters;
		private ECPublicKeyParameters    _publicKeyParameters;
		
		private ECDiffieHellmanKeyDerivationFunction _kdf;
		private CngAlgorithm                         _hashAlgorithm;
		private byte[]                               _hmacKey;
		private byte[]                               _secretPrepend;
		private byte[]                               _secretAppend;
		
		public ECDiffieHellmanKeyDerivationFunction KeyDerivationFunction
		{
			get {
				return _kdf;
			}
			set {
				_kdf = value;
			}
		}

		public CngAlgorithm HashAlgorithm
		{
			get {
				return _hashAlgorithm;
			}
			set {
				_hashAlgorithm = value;
			}
		}
		
		public byte[] HmacKey
		{
			get {
				return _hmacKey;
			}
			set {
				_hmacKey = value;
			}
		}
		
		public byte[] SecretPrepend
		{
			get {
				return _secretPrepend;
			}
			set {
				_secretPrepend = value;
			}
		}
		
		public byte[] SecretAppend
		{
			get {
				return _secretAppend;
			}
			set {
				_secretAppend = value;
			}
		}
		
		public bool UseSecretAgreementAsHmacKey {
			get {
				return (_hmacKey == null);
			}
		}

		
		public ECDiffieHellmanBc() : this(521)
		{
		}
		
		public ECDiffieHellmanBc(Int32 keySize)
		{
			Org.BouncyCastle.Asn1.X9.X9ECParameters ecParams;
			switch (keySize) {
			case 256:
				ecParams = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256r1");
				break;
			case 384:
				ecParams = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp384r1");
				break;
			case 521:
				ecParams = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp521r1");
				break;
			default:
				throw new ArgumentException("ECDiffieHellman key size " + keySize + " not supported");
			}
			_keySize = keySize;
			_domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
			
			// Initialize key generation parameters with new SecureRandom
			Org.BouncyCastle.Security.SecureRandom secureRandom = new Org.BouncyCastle.Security.SecureRandom();
			ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(_domainParameters, secureRandom);
			
			// Generate key pair from domain parameters
			Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator generator = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator();
			generator.Init(keyGenParams);
			Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
			
			// Save the private and public key parameters
			_privateKeyParameters = (ECPrivateKeyParameters) keyPair.Private;
			_publicKeyParameters = (ECPublicKeyParameters) keyPair.Public;
			
			_kdf = ECDiffieHellmanKeyDerivationFunction.Hash;
			_hashAlgorithm = CngAlgorithm.Sha256;
		}
		
		public ECDiffieHellmanPublicKey PublicKey
		{
			get {
				byte[] encoded = _publicKeyParameters.Q.GetEncoded();
				if (encoded[0] != 0x04) {
					throw new Exception("Compressed public key format not accepted");
				}
				
				byte[] magic;
				switch (encoded.Length/2) {
				case 32:
					magic = Encoding.ASCII.GetBytes("ECK1");
					break;
				case 48:
					magic = Encoding.ASCII.GetBytes("ECK3");
					break;
				case 66:
					magic = Encoding.ASCII.GetBytes("ECK5");
					break;
				default:
					throw new Exception("Unknown public key length");
				}
				
				byte[] lengthBytes = BitConverter.GetBytes((uint)(encoded.Length/2));
				byte[] ecdhBlob = new byte[8 + encoded.Length - 1];
				Buffer.BlockCopy(magic, 0, ecdhBlob, 0, 4);
				Buffer.BlockCopy(lengthBytes, 0, ecdhBlob, 4, 4);
				Buffer.BlockCopy(encoded, 1, ecdhBlob, 8, encoded.Length-1);
				return ECDiffieHellmanCngPublicKey.FromByteArray(ecdhBlob, CngKeyBlobFormat.EccPublicBlob);
			}
		}
		
		public byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
		{
			ECPublicKeyParameters publicKey = GetPublicKeyParameters(otherPartyPublicKey);

			// Calculate the shared secret from public key
			Org.BouncyCastle.Crypto.Agreement.ECDHBasicAgreement agreement =
				new Org.BouncyCastle.Crypto.Agreement.ECDHBasicAgreement();
			agreement.Init(_privateKeyParameters);
			byte[] secret = agreement.CalculateAgreement(publicKey).ToByteArray();
			
			// Make sure the secret is always correct length
			byte[] tmpSecret = new byte[(_keySize+7)/8];
			Buffer.BlockCopy(secret, System.Math.Max(0, secret.Length-tmpSecret.Length),
			                 tmpSecret, System.Math.Max(0, tmpSecret.Length-secret.Length),
			                 System.Math.Min(tmpSecret.Length, secret.Length));
			secret = tmpSecret;
			
			if (_kdf == ECDiffieHellmanKeyDerivationFunction.Hash ||
			    _kdf == ECDiffieHellmanKeyDerivationFunction.Hmac) {
				HashAlgorithm hashAlgorithm;
				if (_kdf == ECDiffieHellmanKeyDerivationFunction.Hash) {
					if (_hashAlgorithm.Equals(CngAlgorithm.MD5)) {
						hashAlgorithm = new MD5CryptoServiceProvider();
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha1)) {
						hashAlgorithm = new SHA1CryptoServiceProvider();
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha256)) {
						hashAlgorithm = new SHA256Managed();
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha384)) {
						hashAlgorithm = new SHA384Managed();
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha512)) {
						hashAlgorithm = new SHA512Managed();
					} else {
						throw new Exception("Unsupported hash algorithm type: " + _hashAlgorithm);
					}
				} else {
					byte[] hmacKey = _hmacKey;
					if (UseSecretAgreementAsHmacKey) {
						hmacKey = secret;
					}
					if (_hashAlgorithm.Equals(CngAlgorithm.MD5)) {
						hashAlgorithm = new HMACMD5(hmacKey);
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha1)) {
						hashAlgorithm = new HMACSHA1(hmacKey);
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha256)) {
						hashAlgorithm = new HMACSHA256(hmacKey);
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha384)) {
						hashAlgorithm = new HMACSHA384(hmacKey);
					} else if (_hashAlgorithm.Equals(CngAlgorithm.Sha512)) {
						hashAlgorithm = new HMACSHA512(hmacKey);
					} else {
						throw new Exception("Unsupported hash algorithm type: " + _hashAlgorithm);
					}
				}
				
				hashAlgorithm.Initialize();
				if (_secretPrepend != null) {
					hashAlgorithm.TransformBlock(_secretPrepend, 0, _secretPrepend.Length, _secretPrepend, 0);
				}
				hashAlgorithm.TransformBlock(secret, 0, secret.Length, secret, 0);
				if (_secretAppend != null) {
					hashAlgorithm.TransformBlock(_secretAppend, 0, _secretAppend.Length, _secretAppend, 0);
				}
				hashAlgorithm.TransformFinalBlock(new byte[0], 0, 0);
				return hashAlgorithm.Hash;
			}
			
			throw new Exception("KeyDerivationFunction not implemented yet");
		}
		
		private ECPublicKeyParameters GetPublicKeyParameters(ECDiffieHellmanPublicKey publicKey)
		{
			byte[] ecdhBlob = publicKey.ToByteArray();
			
			int keySize;
			string magic = Encoding.ASCII.GetString(ecdhBlob, 0, 4);
			if (magic.Equals("ECK1")) {
				keySize = 256;
			} else if (magic.Equals("ECK3")) {
				keySize = 384;
			} else if (magic.Equals("ECK5")) {
				keySize = 521;
			} else {
				throw new Exception("Unknown public key type");
			}
			if (keySize != _keySize) {
				throw new Exception("Public key size doesn't match our key size");
			}
			
			byte[] encoded = new byte[1 + ecdhBlob.Length - 8];
			encoded[0] = 0x04;
			Buffer.BlockCopy(ecdhBlob, 8, encoded, 1, ecdhBlob.Length - 8);
			Org.BouncyCastle.Math.EC.ECPoint ecPoint = _domainParameters.Curve.DecodePoint(encoded);
			return new ECPublicKeyParameters(ecPoint, _domainParameters);
		}
	}
}

