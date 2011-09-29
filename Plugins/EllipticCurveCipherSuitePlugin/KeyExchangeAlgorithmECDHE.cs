using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AaltoTLS.PluginInterface;

namespace EllipticCurveCipherSuitePlugin
{
	public class KeyExchangeAlgorithmECDHE : KeyExchangeAlgorithm
	{
		private ECDiffieHellmanCng _ecdhCng;
		private ECDiffieHellmanPublicKey _publicKey;
		
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			// TLSv1.2 not supported because of .NET limitation in getting master secret
			if (version >= ProtocolVersion.TLS1_2 || version >= ProtocolVersion.DTLS1_2) {
				return false;
			}
			return true;
		}

		public override string CertificateKeyAlgorithm
		{
			get { return null; }
		}
		
		public override byte[] GetServerKeys(ProtocolVersion version)
		{
			_ecdhCng = new ECDiffieHellmanCng(256);
			
			UInt16 namedCurve = KeySizeToNamedCurve(256);
			byte[] ecPoint = Blob2Point(_ecdhCng.PublicKey.ToByteArray());
			
			byte[] ret = new byte[4+ecPoint.Length];
			ret[0] = 3;  // ECCurveType.named_curve
			ret[1] = (byte) (namedCurve >> 8);
			ret[2] = (byte) (namedCurve);
			ret[3] = (byte) (ecPoint.Length);
			Buffer.BlockCopy(ecPoint, 0, ret, 4, ecPoint.Length);
			return ret;
		}

		public override byte[] ProcessServerKeys(ProtocolVersion version, byte[] data)
		{
			// Only ECCurveType.named_curve is supported
			if (data[0] != 3) {
				throw new Exception("ECCurveType " + data[0] + " is not supported");
			}
			
			// Create our ECDiffieHellmanCng provider with correct curve
			UInt16 namedCurve = (UInt16) ((data[1] << 8) + data[2]);
			_ecdhCng = new ECDiffieHellmanCng(NamedCurveToKeySize(namedCurve));
			
			// Extract the ECPoint data
			int keyLength = data[3];
			byte[] ecPoint = new byte[keyLength];
			Buffer.BlockCopy(data, 4, ecPoint, 0, keyLength);
			
			// Extract the signature
			byte[] signature = new byte[data.Length-4-keyLength];
			Buffer.BlockCopy(data, 4+keyLength, signature, 0, data.Length-4-keyLength);
			
			// Create the public key from the ecPoint
			byte[] keyBlob = Point2Blob(ecPoint);
			_publicKey = ECDiffieHellmanCngPublicKey.FromByteArray(keyBlob, CngKeyBlobFormat.EccPublicBlob);
			
			return signature;
		}

		public override byte[] GetClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePublicKey publicKey)
		{
			byte[] ecPoint = Blob2Point(_ecdhCng.PublicKey.ToByteArray());
			
			byte[] ret = new byte[1+ecPoint.Length];
			ret[0] = (byte) (ecPoint.Length);
			Buffer.BlockCopy(ecPoint, 0, ret, 1, ecPoint.Length);
			return ret;
		}
		
		public override void ProcessClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePrivateKey privateKey, byte[] data)
		{
			if (data[0] != data.Length-1) {
				throw new Exception("Incorrect ECPoint length");
			}
			
			// Exctract the ECPoint
			byte[] ecPoint = new byte[data.Length-1];
			Buffer.BlockCopy(data, 1, ecPoint, 0, ecPoint.Length);
			
			// Create key blob and public key
			byte[] keyBlob = Point2Blob(ecPoint);
			_publicKey = ECDiffieHellmanCngPublicKey.FromByteArray(keyBlob, CngKeyBlobFormat.EccPublicBlob);
		}
		
		private readonly byte[] SSLv3ID = new byte[] {
			0xd1, 0x34, 0x67, 0x87, 0xae, 0x3a, 0x0d, 0x13, 0x1d, 0xf0, 0x31, 0x25, 0x3c, 0x22, 0xb0, 0x3d,
			0x43, 0xcf, 0xf8, 0x32, 0x2b, 0xfc, 0x59, 0x1f, 0x6a, 0xf6, 0x04, 0xbe, 0xf1, 0x7c, 0x11, 0x9e,
			0x02, 0xac, 0x45, 0x77, 0x83, 0x62, 0xf8, 0x59, 0x0b, 0xed, 0x90, 0x25, 0xee, 0x85, 0x2f, 0x81,
		};
		
		private readonly byte[] TLSv1ID = new byte[] {
			0x3f, 0x88, 0x03, 0xd9, 0xcd, 0x7b, 0xc8, 0xb1, 0xfb, 0xd3, 0x11, 0xe5, 0x84, 0x04, 0xad, 0x50, 
			0x1a, 0x94, 0x24, 0xec, 0x8b, 0x2b, 0xb8, 0x5c, 0xb0, 0x06, 0x5b, 0xeb, 0x19, 0x5b, 0x08, 0xa5,
			0x31, 0x3d, 0xe4, 0xb4, 0xc9, 0xa4, 0x76, 0x13, 0x8c, 0x2a, 0x27, 0xab, 0x51, 0x32, 0x23, 0x43,
		};
		
		public override byte[] GetMasterSecret(PseudoRandomFunction prf, byte[] seed)
		{
			// TODO: Add more PRF IDs and their respective master secrets
			byte[] prfID = prf.CreateDeriveBytes(new byte[0], new byte[0]).GetBytes(48);
			if (CompareArrays(prfID, SSLv3ID)) {
				return GetSSLv3MasterSecret(seed);
			} else if (CompareArrays(prfID, TLSv1ID)) {
				return GetTLSv1MasterSecret(seed);
			} else {
				throw new Exception("Unidentified PRF while getting ECDHE master secret");
			}
		}
		
		private bool CompareArrays(byte[] b1, byte[] b2)
		{
			if (b1 == null || b2 == null) {
				return false;
			}
			if (b1.Length != b2.Length) {
				return false;
			}
			
			for (int i=0; i<b1.Length; i++) {
				if (b1[i] != b2[i]) {
					return false;
				}
			}
			return true;
		}
		
		private byte[] GetSSLv3MasterSecret(byte[] seed)
		{
			_ecdhCng.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
			
			// First generate all three SHA-1 hashes
			_ecdhCng.HashAlgorithm = CngAlgorithm.Sha1;
			_ecdhCng.SecretAppend = seed;
			_ecdhCng.SecretPrepend = Encoding.ASCII.GetBytes("A");
			byte[] sha1_a = _ecdhCng.DeriveKeyMaterial(_publicKey);
			_ecdhCng.SecretPrepend = Encoding.ASCII.GetBytes("BB");
			byte[] sha1_b = _ecdhCng.DeriveKeyMaterial(_publicKey);
			_ecdhCng.SecretPrepend = Encoding.ASCII.GetBytes("CCC");
			byte[] sha1_c = _ecdhCng.DeriveKeyMaterial(_publicKey);
			
			// Then generate all three MD5 hashes
			_ecdhCng.HashAlgorithm = CngAlgorithm.MD5;
			_ecdhCng.SecretPrepend = null;
			_ecdhCng.SecretAppend = sha1_a;
			byte[] md5_a = _ecdhCng.DeriveKeyMaterial(_publicKey);
			_ecdhCng.SecretAppend = sha1_b;
			byte[] md5_b = _ecdhCng.DeriveKeyMaterial(_publicKey);
			_ecdhCng.SecretAppend = sha1_c;
			byte[] md5_c = _ecdhCng.DeriveKeyMaterial(_publicKey);
			
			// Concatenate MD5 hashes to create master secret
			byte[] ret = new byte[48];
			Buffer.BlockCopy(md5_a, 0, ret,  0, 16);
			Buffer.BlockCopy(md5_b, 0, ret, 16, 16);
			Buffer.BlockCopy(md5_c, 0, ret, 32, 16);
			return ret;
		}
		
		private byte[] GetTLSv1MasterSecret(byte[] seed)
		{
			// Use the TLSv1 key derivation included in the ECDH implementation
			_ecdhCng.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Tls;
			_ecdhCng.Label = Encoding.ASCII.GetBytes("master secret");
			_ecdhCng.Seed = seed;
			return _ecdhCng.DeriveKeyMaterial(_publicKey);
		}
		
		private UInt16 KeySizeToNamedCurve(int keySize)
		{
			switch (keySize) {
			case 256:
				// NamedCurve.secp256r1
				return 23;
			case 384:
				// NamedCurve.secp384r1
				return 24;
			case 521:
				// NamedCurve.secp521r1
				return 25;
			default:
				throw new Exception("Unsupported ECDH key size: " + keySize);
			}
		}
		
		private int NamedCurveToKeySize(UInt16 namedCurve)
		{
			switch (namedCurve) {
			case 23:
				return 256;
			case 24:
				return 384;
			case 25:
				return 521;
			default:
				throw new Exception("Unsupported NamedCurve: " + namedCurve);
			}
		}
		
		private byte[] Blob2Point(byte[] blob)
		{
			string blobMagic = Encoding.ASCII.GetString(blob, 0, 4);
			UInt32 keyLength = BitConverter.ToUInt32(blob, 4);
			
			bool keyLengthOk;
			if (blobMagic.Equals("ECK1")) {
				keyLengthOk = (keyLength == 32);
			} else if (blobMagic.Equals("ECK3")) {
				keyLengthOk = (keyLength == 48);
			} else if (blobMagic.Equals("ECK5")) {
				keyLengthOk = (keyLength == 66);
			} else {
				throw new Exception("Unknown ECDH public blob type: " + blobMagic);
			}
			
			if (!keyLengthOk || (blob.Length != 8+2*keyLength)) {
				throw new Exception("Invalid ECC blob key length");
			}
			
			byte[] ret = new byte[1+2*keyLength];
			ret[0] = 4; // uncompressed
			Buffer.BlockCopy(blob, 8, ret, 1, ret.Length-1);
			return ret;
		}
		
		private byte[] Point2Blob(byte[] point)
		{
			// Only uncompressed supported
			if (point[0] != 4) {
				throw new Exception("Unsupported ECPoint format: " + point[0]);
			}
			
			string blobMagic;
			UInt32 keyLength = (UInt32) ((point.Length-1)/2);
			
			switch (keyLength*8) {
			case 256:
				blobMagic = "ECK1";
				break;
			case 384:
				blobMagic = "ECK3";
				break;
			case 521:
				blobMagic = "ECK5";
				break;
			default:
				throw new Exception("Unknown ECPoint key length");
			}
			
			byte[] blobMagicData = Encoding.ASCII.GetBytes(blobMagic);
			byte[] keyLengthData = BitConverter.GetBytes(keyLength);
			
			byte[] ret = new byte[8+2*keyLength];
			Buffer.BlockCopy(blobMagicData, 0, ret, 0, 4);
			Buffer.BlockCopy(keyLengthData, 0, ret, 4, 4);
			Buffer.BlockCopy(point, 1, ret, 8, ret.Length-8);
			return ret;
		}
	}
}

