using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;


namespace ECCTest
{
	class MainClass
	{
		protected static void PrintBytes(string name, byte[] data)
		{
			Console.Write(name + "[" + data.Length + "]:");
			for (int i=0; i<data.Length; i++) {
				if (i%16 == 0) Console.WriteLine("");
				Console.Write(data[i].ToString("x").PadLeft(2, '0') + " ");
			}
			Console.WriteLine("");
		}
		
		public static void Main (string[] args)
		{
			if (args.Length != 2) {
				Console.WriteLine("Usage: ECCTest.exe ecdsaca.der ecdsakey.cng");
				return;
			}
			X509Certificate2 cert = new X509Certificate2(args[0]);
			PublicKey publicKey = cert.PublicKey;
			ECDsaCng ecdsaPublicKey = GetECDSAFromPublicKey(publicKey);
			ecdsaPublicKey.HashAlgorithm = CngAlgorithm.Sha512;
			
			byte[] cngBlob = File.ReadAllBytes(args[1]);
			CngKey cngKey = CngKey.Import(cngBlob, CngKeyBlobFormat.GenericPrivateBlob, CngProvider.MicrosoftSoftwareKeyStorageProvider);
			ECDsaCng ecdsaPrivateKey = new ECDsaCng(cngKey);
			ecdsaPrivateKey.HashAlgorithm = CngAlgorithm.Sha512;
			
			byte[] data = new byte[256];
			for (int i=0; i<data.Length; i++) {
				data[i] = (byte)i;
			}
			
			byte[] signature = ecdsaPrivateKey.SignData(data);
			PrintBytes("signature", signature);
			Console.WriteLine("Signature verified: " + ecdsaPublicKey.VerifyData(data, signature));
			
			ECDiffieHellmanBc alice = new ECDiffieHellmanBc();
			ECDiffieHellmanCng bob  = new ECDiffieHellmanCng();
			
			byte[] aliceKey = alice.DeriveKeyMaterial(bob.PublicKey);
			byte[] bobKey   = bob.DeriveKeyMaterial(alice.PublicKey);
			
			PrintBytes("alice key", aliceKey);
			PrintBytes("bob key", bobKey);
			
			
			Console.WriteLine("Running CMAC test");
			byte[] keyBytes = new byte[24];
			KeyParameter key = new KeyParameter(keyBytes);
			
			byte[] hashedData = new byte[31];
			for (int i=0; i<hashedData.Length; i++)
				hashedData[i] = (byte) i;
			CMac cmac = new CMac(new AesEngine(), 128);
			cmac.Init(key);
			cmac.BlockUpdate(hashedData, 0, hashedData.Length);
			
			byte[] hash = new byte[cmac.GetMacSize()];
			cmac.DoFinal(hash, 0);
			PrintBytes("hash", hash);
		}
		
		private static string P256OID = "1.2.840.10045.3.1.7";
		private static string P384OID = "1.3.132.0.34";
		private static string P521OID = "1.3.132.0.35";
		
		private static ECDsaCng GetECDSAFromPublicKey(PublicKey publicKey)
		{
			if (!publicKey.Oid.Value.Equals("1.2.840.10045.2.1")) {
				throw new Exception("ECDSA signature verification requires ECDSA public key");
			}

			string curveOid = DER2OID(publicKey.EncodedParameters.RawData);
			if (curveOid == null) {
				throw new Exception("Unsupported ECDSA public key parameters");
			}
			
			byte[] keyData = publicKey.EncodedKeyValue.RawData;
			if (keyData[0] != 0x04) {
				throw new Exception("Invalid first byte of ECDSA public key: " + keyData[0]);
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
			return ecdsaKey;
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
	}
}
