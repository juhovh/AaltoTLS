//
// PEM2CNG
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
using System.IO;
using System.Text;

namespace PEM2CNG
{
	class MainClass
	{
		const string ecprivheader = "-----BEGIN EC PRIVATE KEY-----";
		const string ecprivfooter   = "-----END EC PRIVATE KEY-----";
		
		const string ECDH_PUBLIC_P256_MAGIC   = "ECK1";
		const string ECDH_PRIVATE_P256_MAGIC  = "ECK2";
		const string ECDH_PUBLIC_P384_MAGIC   = "ECK3";
		const string ECDH_PRIVATE_P384_MAGIC  = "ECK4";
		const string ECDH_PUBLIC_P521_MAGIC   = "ECK5";
		const string ECDH_PRIVATE_P521_MAGIC  = "ECK6";
		
		const string ECDSA_PUBLIC_P256_MAGIC  = "ECS1";
		const string ECDSA_PRIVATE_P256_MAGIC = "ECS2";
		const string ECDSA_PUBLIC_P384_MAGIC  = "ECS3";
		const string ECDSA_PRIVATE_P384_MAGIC = "ECS4";
		const string ECDSA_PUBLIC_P521_MAGIC  = "ECS5";
		const string ECDSA_PRIVATE_P521_MAGIC = "ECS6";

		const string P256OID = "1.2.840.10045.3.1.7";
		const string P384OID = "1.3.132.0.34";
		const string P521OID = "1.3.132.0.35";
		
		public static string DER2OID(byte[] oid)
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
		
		public static byte[] DecodeECDSAKey(byte[] der)
		{
			try {
				int pos = 0;
				
				// Check the type is correct
				if (der[pos++] != 0x30) {
					throw new Exception("ECDSA key type incorrect");
				}
				
				// Check the length matches
				int length;
				if (der[pos] <= 0x80) {
					length = der[pos];
					pos += 1;
				} else if (der[pos] == 0x81) {
					length = der[pos+1];
					pos += 2;
				} else if (der[pos] == 0x82) {
					length = (der[pos+1] << 8) | der[pos+2];
					pos += 3;
				} else {
					throw new Exception("ECDSA key length too large");
				}
				if (length != der.Length-pos) {
					throw new Exception("ECDSA key length incorrect");
				}
				
				// Check that version is 1, we can't handle other versions
				if (der[pos] != 0x02 || der[pos+1] != 0x01 || der[pos+2] != 0x01) {
					throw new Exception("ECDSA key version incorrect");
				}
				pos += 3;
				
				// Check type is int and get private key length
				if (der[pos] != 0x04 || der[pos+1] > 128) {
					throw new Exception("ECDSA key length is not valid");
				}
				int privatekeylength = der[pos+1];
				pos += 2;
				
				// Get the private key from bytes
				byte[] privateKey = new byte[privatekeylength];
				Buffer.BlockCopy(der, pos, privateKey, 0, privatekeylength);
				pos += privatekeylength;
				
				// Check that the next array is correct length
				if (der[pos] != 0xa0 || der[pos+1] > 128) {
					throw new Exception("ECDSA key OID length is not valid");
				}
				int oidlength = der[pos+1];
				pos += 2;
				
				// Get the OID in DER form from bytes
				byte[] derOID = new byte[oidlength];
				Buffer.BlockCopy(der, pos, derOID, 0, oidlength);
				pos += oidlength;
				
				// Check the second array and its length
				if (der[pos++] != 0xa1) {
					throw new Exception("ECDSA public key array is not valid");
				}
				int datalen;
				if (der[pos] <= 0x80) {
					datalen = der[pos];
					pos += 1;
				} else if (der[pos] == 0x81) {
					datalen = der[pos+1];
					pos += 2;
				} else {
					throw new Exception("ECDSA public key array length is not valid");
				}
				if (datalen != der.Length-pos) {
					throw new Exception("ECDSA public key array length too large");
				}
				
				// Check the data contents and length
				if (der[pos++] != 0x03) {
					throw new Exception("ECDSA public key is not valid");
				}
				int publickeylength;
				if (der[pos] <= 0x80) {
					publickeylength = der[pos];
					pos += 1;
				} else if (der[pos] == 0x81) {
					publickeylength = der[pos+1];
					pos += 2;
				} else {
					throw new Exception("ECDSA public key length is too large");
				}
				if (publickeylength != der.Length-pos || ((publickeylength-2)%2) != 0) {
					throw new Exception("ECDSA public key length is not valid");
				}
				
				// Skip all the null bytes
				while (der[pos] == 0) {
					pos++;
				}
				
				// Check the point type
				int ecPointType = der[pos++];
				if (ecPointType != 4) {
					throw new Exception("Only uncompressed public key supported");
				}
				
				byte[] publicKeyX = new byte[(publickeylength-2)/2];
				byte[] publicKeyY = new byte[(publickeylength-2)/2];
				Buffer.BlockCopy(der, pos, publicKeyX, 0, publicKeyX.Length);
				pos += publicKeyX.Length;
				Buffer.BlockCopy(der, pos, publicKeyY, 0, publicKeyY.Length);
				pos += publicKeyY.Length;
				
				if (pos != der.Length) {
					throw new Exception("ECDSA public key has additional bytes");
				}
				
				string stringOid = DER2OID(derOID);
				if (stringOid == null) {
					throw new Exception("Error decoding private key OID");
				}
				
				int keyLength;
				string keyMagic;
				if (stringOid.Equals(P256OID)) {
					keyLength = 32;
					keyMagic = ECDSA_PRIVATE_P256_MAGIC;
				} else if (stringOid.Equals(P384OID)) {
					keyLength = 48;
					keyMagic = ECDSA_PRIVATE_P384_MAGIC;
				} else if (stringOid.Equals(P521OID)) {
					keyLength = 66;
					keyMagic = ECDSA_PRIVATE_P521_MAGIC;
				} else {
					throw new Exception("Unsupported key OID");
				}
				
				if (publicKeyX.Length > keyLength ||
				    publicKeyY.Length > keyLength ||
				    privateKey.Length > keyLength) {
					throw new Exception("ECDSA key length too large for the key type");
				}

				MemoryStream memStream = new MemoryStream();
				BinaryWriter writer = new BinaryWriter(memStream);
				writer.Write(Encoding.ASCII.GetBytes(keyMagic));
				writer.Write((uint) keyLength);
				
				if (publicKeyX.Length < keyLength) {
					writer.Write(new byte[keyLength-publicKeyX.Length]);
				}
				writer.Write(publicKeyX);
				
				if (publicKeyY.Length < keyLength) {
					writer.Write(new byte[keyLength-publicKeyY.Length]);
				}
				writer.Write(publicKeyY);
				
				if (privateKey.Length < keyLength) {
					writer.Write(new byte[keyLength-privateKey.Length]);
				}
				writer.Write(privateKey);
				return memStream.ToArray();
			} catch (Exception) {
			}
			
			return null;
		}
		
		public static byte[] DecodePEMKey(string pemstr)
		{
			if (pemstr.StartsWith(ecprivheader) && pemstr.EndsWith(ecprivfooter)) {
				StringBuilder sb = new StringBuilder(pemstr);
				sb.Replace(ecprivheader, "");
				sb.Replace(ecprivfooter, "");
				string base64str = sb.ToString().Trim();
				
				try {
					byte[] ecdsaKey = Convert.FromBase64String(base64str);
					byte[] cngKey = DecodeECDSAKey(ecdsaKey);
					if (cngKey != null) {
						return cngKey;
					} else {
						Console.WriteLine("Decoding ECDSA private key failed");
					}
				} catch (FormatException) {
					Console.WriteLine("EC private key is invalid base64");
				}
			} else {
				Console.WriteLine("Unsupported PEM key format");
			}
			
			return null;
		}
		
		public static void Main (string[] args)
		{
			if (args.Length != 2) {
				Console.WriteLine("Usage: PEM2CNG.exe key.pem key.cng");
				return;
			}
			String pemfilename = args[0].Trim();
			String cngfilename = args[1].Trim();

			String pemstr;
			using (StreamReader sr = File.OpenText(pemfilename)) {
				pemstr = sr.ReadToEnd().Trim();
			}

			byte[] cngdata = DecodePEMKey(pemstr);
			if (cngdata != null) {
				File.WriteAllBytes(cngfilename, cngdata);
			}
		}
	}
}

