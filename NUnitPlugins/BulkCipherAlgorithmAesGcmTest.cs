//
// BulkCipherAlgorithmAesGcmTest
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

using NUnit.Framework;
using System;
using System.Security.Cryptography;

namespace BaseCipherSuitePlugin
{
	[TestFixture]
	public class BulkCipherAlgorithmAesGcmTest
	{
		private byte[] StringToByteArray (String str)
		{
			if ((str.Length % 2) != 0) {
				throw new ArgumentException("Invalid string length");
			}
			
			byte[] bytes = new byte[str.Length / 2];
			for (int i = 0; i<str.Length; i+=2) {
				bytes[i/2] = Convert.ToByte (str.Substring(i, 2), 16);
			}
			return bytes;
		}
		
		private void CheckVector (byte[] key, byte[] plaintext, byte[] additional, byte[] nonce, byte[] ciphertext, byte[] tag)
		{
			BulkCipherAlgorithmAesGcm cipher = new BulkCipherAlgorithmAesGcm(key.Length*8, tag.Length*8);
			ICryptoTransform encryptor = cipher.CreateEncryptor(key, nonce, additional);
			byte[] enc = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
			ICryptoTransform decryptor = cipher.CreateDecryptor(key, nonce, additional);
			byte[] dec = decryptor.TransformFinalBlock(enc, 0, enc.Length);
			
			byte[] result = new byte[ciphertext.Length + tag.Length];
			Buffer.BlockCopy(ciphertext, 0, result, 0, ciphertext.Length);
			Buffer.BlockCopy(tag, 0, result, ciphertext.Length, tag.Length);
			
			Assert.AreEqual(result, enc);
			Assert.AreEqual(plaintext, dec);
		}
		
		[Test]
		public void Vector1 ()
		{
			byte[] key = StringToByteArray("1014f74310d1718d1cc8f65f033aaf83");
			byte[] plaintext = StringToByteArray("");
			byte[] additional = StringToByteArray("");
			byte[] nonce = StringToByteArray("6bb54c9fd83c12f5ba76cc83f7650d2c");
			byte[] ciphertext = StringToByteArray("");
			byte[] tag = StringToByteArray("0b6b57db309eff920c8133b8691e0cac");
			CheckVector (key, plaintext, additional, nonce, ciphertext, tag);
		}
		
		[Test]
		public void Vector2 ()
		{
			byte[] key = StringToByteArray("2397f163a0cb50b0e8c85f909b96adc1");
			byte[] plaintext = StringToByteArray("");
			byte[] additional = StringToByteArray("");
			byte[] nonce = StringToByteArray("97a631f5f6fc928ffce32ee2c92f5e50");
			byte[] ciphertext = StringToByteArray("");
			byte[] tag = StringToByteArray("3b74cca7bcdc07c8f8d4818de714f2");
			CheckVector (key, plaintext, additional, nonce, ciphertext, tag);
		}
		
		[Test]
		public void Vector3 ()
		{
			byte[] key = StringToByteArray("b5beefbdd23360f2dd1e6e3c1ddbfebf");
			byte[] plaintext = StringToByteArray("");
			byte[] additional = StringToByteArray("f9ebf242b616a42e2057ede3b56b4c27349fed148817a710654de75d1cfc5f6304709b46ef1e2ccb42f877c50f484f8a8c6b0a25cff61d9537c3fd0c69bbc6ef21cbec8986cbc9b6e87963b8d9db91b7134afe69d3d9dec3a76b6c645f9c5528968f27396cc9e989d589369c90bbfefb249e3fa416451bc3d6592cc5feefbd76");
			byte[] nonce = StringToByteArray("81a8494f85be635d71e5663789162494");
			byte[] ciphertext = StringToByteArray("");
			byte[] tag = StringToByteArray("159a642185e0756d46f1db57af975fa3");
			CheckVector (key, plaintext, additional, nonce, ciphertext, tag);
		}
		
		[Test]
		public void Vector4 ()
		{
			byte[] key = StringToByteArray("ce0f8cfe9d64c4f4c045d11b97c2d918");
			byte[] plaintext = StringToByteArray("dfff250d380f363880963b42d6913c1ba11e8edf7c4ab8b76d79ccbaac628f548ee542f48728a9a2620a0d69339c8291e8d398440d740e310908cdee7c273cc91275ce7271ba12f69237998b07b789b3993aaac8dc4ec1914432a30f5172f79ea0539bd1f70b36d437e5170bc63039a5280816c05e1e41760b58e35696cebd55");
			byte[] additional = StringToByteArray("");
			byte[] nonce = StringToByteArray("ad4c3627a494fc628316dc03faf81db8");
			byte[] ciphertext = StringToByteArray("0de73d9702d9357c9e8619b7944e40732ac2f4dd3f1b42d8d7f36acb1f1497990d0ec3d626082cdb1384ec72a4c1d98955ba2a3aae6d81b24e9ce533eb5ede7210ae4a06d43f750138b8914d754d43bce416fee799cc4dd03949acedc34def7d6bde6ba41a4cf03d209689a3ad181f1b6dcf76ca25c87eb1c7459cc9f95ddc57");
			byte[] tag = StringToByteArray("5f6a3620e59fe8977286f502d0da7517");
			CheckVector (key, plaintext, additional, nonce, ciphertext, tag);
		}
		
		[Test]
		public void Vector5 ()
		{
			byte[] key = StringToByteArray("839664bb6c352e64714254e4d590fb28");
			byte[] plaintext = StringToByteArray("752c7e877663d10f90e5c96cce2686f4aa846a12272a0aba399e860f2838827c7c718365e704084fbe1e68adb27ad18e993c800da2e05bcaf44b651944bde766e7b3ac22f068b525dd0b80b490b3498d7b7199f60faf69fee338087f7a752fb52147034de8922a3ed73b512d9c741f7bac1206e9b0871a970271f50688038ab7");
			byte[] additional = StringToByteArray("4d75a10ff29414c74d945da046ed45dc02783da28c1ee58b59cbc6f953dd09788b6d513f7366be523e6c2d877c36795942690ce9543050f7ab6f6f647d262360994f7f892e9f59941a8d440619fda8aa20350be14c13d7924c0451c1489da9a0cafd759c3798776245170ad88dbceb3cacde6ba122b656601ccb726e99d54115");
			byte[] nonce = StringToByteArray("5482db71d85039076a541aaba287e7f7");
			byte[] ciphertext = StringToByteArray("c7ee1c32f8bc0181b53ce57f116e863481db6f21666ba3fa19bd99ce83eee2d573388a0459dfede92e701982a9cc93d697f313062dbea9866526f1d720a128ab97452a35f458637116f7d9294ffc76079539061dfeff9642a049db53d89f2480a6d74a05ff25d46d7048cc16d43f7888b5aff9957b5dc828973afccff63bd42a");
			byte[] tag = StringToByteArray("63c8aa731a60076725cd5f9973eeadb5");
			CheckVector (key, plaintext, additional, nonce, ciphertext, tag);
		}
		
		// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-test-vectors.tar.gz
		[Test]
		public void Vector6 ()
		{
			byte[] key = StringToByteArray("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
			byte[] plaintext = StringToByteArray("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
			byte[] additional = StringToByteArray("feedfacedeadbeeffeedfacedeadbeefabaddad2");
			byte[] nonce = StringToByteArray("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
			byte[] ciphertext = StringToByteArray("5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f");
			byte[] tag = StringToByteArray("a44a8266ee1c8eb0c8b5d4cf5ae9f19a");
			CheckVector (key, plaintext, additional, nonce, ciphertext, tag);
		}
	}
}

