//
// PEM2XML
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
using System.Security.Cryptography;

namespace PEM2XML
{
	class MainClass
	{
		const string rsaprivheader = "-----BEGIN RSA PRIVATE KEY-----";
		const string rsaprivfooter   = "-----END RSA PRIVATE KEY-----";
		const string dsaprivheader = "-----BEGIN DSA PRIVATE KEY-----";
		const string dsaprivfooter   = "-----END DSA PRIVATE KEY-----";

		public static byte[] ReadVector(BinaryReader binaryReader)
		{
			byte tmp;

			tmp = binaryReader.ReadByte();
			if (tmp != 0x02) {
				return null;
			}

			int count;
			tmp = binaryReader.ReadByte();
			if (tmp == 0x81) {
				count = binaryReader.ReadByte();
			} else if (tmp == 0x82) {
				byte hiByte = binaryReader.ReadByte();
				byte loByte = binaryReader.ReadByte();
				count = (hiByte << 8) | loByte;
			} else {
				count = tmp;
			}

			return binaryReader.ReadBytes(count);
		}

		public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] rsaKey)
		{
			byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

			MemoryStream memoryStream = new MemoryStream(rsaKey);
			BinaryReader binaryReader = new BinaryReader(memoryStream);

			try {
				// Skip either one or two bytes
				ushort tmp = binaryReader.ReadUInt16();
				switch (tmp) {
				case 0x8130:
					binaryReader.ReadByte();
					break;
				case 0x8230:
					binaryReader.ReadInt16();
					break;
				default:
					return null;
				}

				// Check that version number is correct
				if (binaryReader.ReadUInt16() != 0x0102) {
					return null;
				}

				// Check for null byte
				if (binaryReader.ReadByte() != 0x00) {
					return null;
				}

				MODULUS = ReadVector(binaryReader);
				E = ReadVector(binaryReader);
				D = ReadVector(binaryReader);
				P = ReadVector(binaryReader);
				Q = ReadVector(binaryReader);
				DP = ReadVector(binaryReader);
				DQ = ReadVector(binaryReader);
				IQ = ReadVector(binaryReader);

				RSAParameters rsaParams = new RSAParameters();
				rsaParams.Modulus = MODULUS;
				rsaParams.Exponent = E;
				rsaParams.D = D;
				rsaParams.P = P;
				rsaParams.Q = Q;
				rsaParams.DP = DP;
				rsaParams.DQ = DQ;
				rsaParams.InverseQ = IQ;

				RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
				rsa.ImportParameters(rsaParams);
				return rsa;
			} catch (Exception) {}

			return null;
		}

		public static DSACryptoServiceProvider DecodeDSAPrivateKey(byte[] dsaKey)
		{
			byte[] P, Q, G, Y, X;

			MemoryStream memoryStream = new MemoryStream(dsaKey);
			BinaryReader binaryReader = new BinaryReader(memoryStream);

			try {
				// Skip either one or two bytes
				ushort tmp = binaryReader.ReadUInt16();
				switch (tmp) {
				case 0x8130:
					binaryReader.ReadByte();
					break;
				case 0x8230:
					binaryReader.ReadInt16();
					break;
				default:
					return null;
				}

				// Check that version number is correct
				if (binaryReader.ReadUInt16() != 0x0102) {
					return null;
				}

				// Check for null byte
				if (binaryReader.ReadByte() != 0x00) {
					return null;
				}

				P = ReadVector(binaryReader);
				Q = ReadVector(binaryReader);
				G = ReadVector(binaryReader);
				Y = ReadVector(binaryReader);
				X = ReadVector(binaryReader);

				DSAParameters dsaParams = new DSAParameters();
				dsaParams.P = P;
				dsaParams.Q = Q;
				dsaParams.G = G;
				dsaParams.Y = Y;
				dsaParams.X = X;

				DSACryptoServiceProvider dsa = new DSACryptoServiceProvider();
				dsa.ImportParameters(dsaParams);
				return dsa;
			} catch (Exception) {}
			return null;
		}

		public static string DecodePEMKey(string pemstr)
		{
			if (pemstr.StartsWith(rsaprivheader) && pemstr.EndsWith(rsaprivfooter)) {
				StringBuilder sb = new StringBuilder(pemstr);
				sb.Replace(rsaprivheader, "");
				sb.Replace(rsaprivfooter, "");
				string base64str = sb.ToString().Trim();

				try {
					byte[] rsaKey = Convert.FromBase64String(base64str);
					RSACryptoServiceProvider rsa = DecodeRSAPrivateKey(rsaKey);
					if (rsa != null) {
						return rsa.ToXmlString(true);
					} else {
						Console.WriteLine("Decoding RSA private key failed");
					}
				} catch (FormatException) {
					Console.WriteLine("RSA private key is invalid base64");
				}
			} else if (pemstr.StartsWith(dsaprivheader) && pemstr.EndsWith(dsaprivfooter)) {
				StringBuilder sb = new StringBuilder(pemstr);
				sb.Replace(dsaprivheader, "");
				sb.Replace(dsaprivfooter, "");
				string base64str = sb.ToString().Trim();

				try {
					byte[] dsaKey = Convert.FromBase64String(base64str);
					DSACryptoServiceProvider dsa = DecodeDSAPrivateKey(dsaKey);
					if (dsa != null) {
						return dsa.ToXmlString(true);
					} else {
						Console.WriteLine("Decoding DSA private key failed");
					}
				} catch (FormatException) {
					Console.WriteLine("DSA private key is invalid base64");
				}
			} else {
				Console.WriteLine("Unsupported PEM key format");
			}

			return null;
		}

		public static void Main(string[] args)
		{
			if (args.Length != 2) {
				Console.WriteLine("Usage: PEM2XML.exe key.pem key.xml");
				return;
			}
			String pemfilename = args[0].Trim();
			String xmlfilename = args[1].Trim();

			String pemstr;
			using (StreamReader sr = File.OpenText(pemfilename)) {
				pemstr = sr.ReadToEnd().Trim();
			}

			string xmlstr = DecodePEMKey(pemstr);
			if (xmlstr != null) {
				File.WriteAllText(xmlfilename, xmlstr);
			}
		}
	}
}
