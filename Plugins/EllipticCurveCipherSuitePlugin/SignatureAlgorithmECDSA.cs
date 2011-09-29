using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AaltoTLS.PluginInterface;

namespace EllipticCurveCipherSuitePlugin
{
	public class SignatureAlgorithmECDSA : SignatureAlgorithm
	{
		private readonly string P256OID = "1.2.840.10045.3.1.7";
		private readonly string P384OID = "1.3.132.0.34";
		private readonly string P521OID = "1.3.132.0.35";
		
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

		private CngAlgorithm GetCngAlgorithm(HashAlgorithm hashAlgorithm)
		{
			CngAlgorithm cngAlgorithm = null;
			if (hashAlgorithm == null) {
				cngAlgorithm = CngAlgorithm.Sha1;
			} else if (hashAlgorithm is MD5) {
				cngAlgorithm = CngAlgorithm.MD5;
			} else if (hashAlgorithm is SHA1) {
				cngAlgorithm = CngAlgorithm.Sha1;
			} else if (hashAlgorithm is SHA256) {
				cngAlgorithm = CngAlgorithm.Sha256;
			} else if (hashAlgorithm is SHA384) {
				cngAlgorithm = CngAlgorithm.Sha384;
			} else if (hashAlgorithm is SHA512) {
				cngAlgorithm = CngAlgorithm.Sha512;
			}
			return cngAlgorithm;
		}
		
		public override bool SupportsHashAlgorithmType(byte hashAlgorithm)
		{
			// Supported HashAlgorithms listed here
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
				string magic = Encoding.ASCII.GetString(keyData, 0, 4);
				if (magic.Equals("ECS2") || magic.Equals("ECS4") || magic.Equals("ECS6")) {
					CngKey cngKey = CngKey.Import(keyData, CngKeyBlobFormat.EccPrivateBlob);
					ECDsaCng ecdsa = new ECDsaCng(cngKey);
					return new CertificatePrivateKey(ecdsa);
				}
			} catch (Exception) {}
			
			return null;
		}

		public override byte[] SignData(byte[] buffer, HashAlgorithm hashAlgorithm, CertificatePrivateKey privateKey)
		{
			if (!(privateKey.Algorithm is ECDsaCng)) {
				throw new Exception("ECDSA signature requires ECDSA private key");
			}
			
			ECDsaCng ecdsaKey = (ECDsaCng) privateKey.Algorithm;
			ecdsaKey.HashAlgorithm = GetCngAlgorithm(hashAlgorithm);
			
			byte[] signature = ecdsaKey.SignData(buffer);
			signature = DEREncodeSignature(signature);
			return signature;
		}

		public override bool VerifyData(byte[] buffer, HashAlgorithm hashAlgorithm, CertificatePublicKey publicKey, byte[] signature)
		{
			if (!CertificateKeyAlgorithm.Equals(publicKey.Oid)) {
				throw new Exception("ECDSA signature verification requires ECDSA public key");
			}

			string curveOid = DER2OID(publicKey.Parameters);
			if (curveOid == null) {
				throw new Exception("Unsupported ECDSA public key parameters");
			}
			
			byte[] keyData = publicKey.KeyValue;
			if (keyData[0] != 0x04) {
				throw new Exception("Only uncompressed ECDSA keys supported, format: " + keyData[0]);
			}
			
			UInt32 keyLength;
			byte[] blobMagic;
			if (curveOid.Equals(P256OID)) {
				keyLength = 32;
				blobMagic = Encoding.ASCII.GetBytes("ECS1");
			} else if (curveOid.Equals(P384OID)) {
				keyLength = 48;
				blobMagic = Encoding.ASCII.GetBytes("ECS3");
			} else if (curveOid.Equals(P521OID)) {
				keyLength = 66;
				blobMagic = Encoding.ASCII.GetBytes("ECS5");
			} else {
				throw new Exception("Unsupported ECC curve type OID: " + curveOid);
			}
			
			if (2*keyLength != keyData.Length-1) {
				throw new Exception("Invalid length of ECDSA public key: " + keyData.Length +
				                    " (should be " + (1+2*keyLength) + ")");
			}
			byte[] lengthData = BitConverter.GetBytes(keyLength);
			
			// Create the ECC public blob for ECDsaCng class
			byte[] eccBlob = new byte[8+2*keyLength];
			Buffer.BlockCopy(blobMagic, 0, eccBlob, 0, 4);
			Buffer.BlockCopy(lengthData, 0, eccBlob, 4, 4);
			Buffer.BlockCopy(keyData, 1, eccBlob, 8, (int) (2*keyLength));
			
			CngKey cngKey = CngKey.Import(eccBlob, CngKeyBlobFormat.EccPublicBlob);
			ECDsaCng ecdsaKey = new ECDsaCng(cngKey);
			ecdsaKey.HashAlgorithm = GetCngAlgorithm(hashAlgorithm);
			
			return ecdsaKey.VerifyData(buffer, DERDecodeSignature(signature, (int)keyLength));
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
		
		private static byte[] DERDecodeSignature(byte[] data, int sigLength)
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
