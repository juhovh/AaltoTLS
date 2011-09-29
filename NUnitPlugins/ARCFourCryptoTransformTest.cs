//
// ARCFourCryptoTransformTest
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

namespace ARCFourCipherSuitePlugin
{
	[TestFixture]
	public class ARCFourCryptoTransformTest
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
		
		/* Test vectors from http://www.freemedialibrary.com/index.php/RC4_test_vectors */
		
		private void CheckVector (byte[] key, byte[] plaintext, byte[] ciphertext)
		{
			BulkCipherAlgorithmARCFour cipher = new BulkCipherAlgorithmARCFour(key.Length*8);
			ICryptoTransform encryptor = cipher.CreateEncryptor(key, null);
			byte[] enc = encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
			ICryptoTransform decryptor = cipher.CreateDecryptor(key, null);
			byte[] dec = decryptor.TransformFinalBlock(enc, 0, enc.Length);
			Assert.AreEqual(ciphertext, enc);
			Assert.AreEqual(plaintext, dec);
		}
		
		[Test]
		public void Vector1 ()
		{
			byte[] key = StringToByteArray("0123456789abcdef");
			byte[] plaintext = StringToByteArray("0123456789abcdef");
			byte[] ciphertext = StringToByteArray("75b7878099e0c596");
			CheckVector (key, plaintext, ciphertext);
		}
		
		[Test]
		public void Vector2 ()
		{
			byte[] key = StringToByteArray("0123456789abcdef");
			byte[] plaintext = StringToByteArray("0000000000000000");
			byte[] ciphertext = StringToByteArray("7494c2e7104b0879");
			CheckVector (key, plaintext, ciphertext);
		}
		
		[Test]
		public void Vector3 ()
		{
			byte[] key = StringToByteArray("0000000000000000");
			byte[] plaintext = StringToByteArray("0000000000000000");
			byte[] ciphertext = StringToByteArray("de188941a3375d3a");
			CheckVector (key, plaintext, ciphertext);
		}
		
		[Test]
		public void Vector4 ()
		{
			byte[] key = StringToByteArray("ef012345");
			byte[] plaintext = StringToByteArray("00000000000000000000");
			byte[] ciphertext = StringToByteArray("d6a141a7ec3c38dfbd61");
			CheckVector (key, plaintext, ciphertext);
		}
		
		[Test]
		public void Vector5 ()
		{
			byte[] key = StringToByteArray("0123456789abcdef");
			byte[] plaintext = StringToByteArray(
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101010101010101010101010101010101" +
			    "0101");
			byte[] ciphertext = StringToByteArray(
			    "7595c3e6114a09780c4ad452338e1ffd9a" +
				"1be9498f813d76533449b6778dcad8c78a" +
				"8d2ba9ac66085d0e53d59c26c2d1c490c1" +
				"ebbe0ce66d1b6b1b13b6b919b847c25a91" +
				"447a95e75e4ef16779cde8bf0a95850e32" +
				"af9689444fd377108f98fdcbd4e7265675" +
				"00990bcc7e0ca3c4aaa304a387d20f3b8f" +
				"bbcd42a1bd311d7a4303dda5ab078896ae" +
				"80c18b0af66dff319616eb784e495ad2ce" +
				"90d7f772a81747b65f62093b1e0db9e5ba" +
				"532fafec47508323e671327df9444432cb" +
				"7367cec82f5d44c0d00b67d650a075cd4b" +
				"70dedd77eb9b10231b6b5b741347396d62" +
				"897421d43df9b42e446e358e9c11a9b218" +
				"4ecbef0cd8e7a877ef968f1390ec9b3d35" +
				"a5585cb009290e2fcde7b5ec66d9084be4" +
				"4055a619d9dd7fc3166f9487f7cb272912" +
				"426445998514c15d53a18c864ce3a2b755" +
				"5793988126520eacf2e3066e230c91bee4" +
				"dd5304f5fd0405b35bd99c73135d3d9bc3" +
				"35ee049ef69b3867bf2d7bd1eaa595d8bf" +
				"c0066ff8d31509eb0c6caa006c807a623e" +
				"f84c3d33c195d23ee320c40de0558157c8" +
				"22d4b8c569d849aed59d4e0fd7f379586b" +
				"4b7ff684ed6a189f7486d49b9c4bad9ba2" +
				"4b96abf924372c8a8fffb10d55354900a7" +
				"7a3db5f205e1b99fcd8660863a159ad4ab" +
				"e40fa48934163ddde542a6585540fd683c" +
				"bfd8c00f12129a284deacc4cdefe58be71" +
				"37541c047126c8d49e2755ab181ab7e940" +
				"b0c0");
			CheckVector (key, plaintext, ciphertext);
		}
		
		[Test]
		public void Vector6 ()
		{
			byte[] key = StringToByteArray("fb029e3031323334");
			byte[] plaintext = StringToByteArray(
			    "aaaa0300000008004500004e661a000080" +
				"11be640a0001220affffff00890089003a" +
				"000080a601100001000000000000204543" +
				"454a454845434643455046454549454646" +
				"4343414341434143414341414100002000" +
				"011bd0b604");
			byte[] ciphertext = StringToByteArray(
			    "f69c5806bd6ce84626bcbefb9474650aad" +
				"1f7909b0f64d5f58a503a258b7ed22eb0e" +
				"a64930d3a056a55742fcce141d485f8aa8" +
				"36dea18df42c5380805ad0c61a5d6f58f4" +
				"1040b24b7d1a693856ed0d4398e7aee3bf" +
				"0e2a2ca8f7");
			CheckVector (key, plaintext, ciphertext);
		}
		
		[Test]
		public void Vector7 ()
		{
			byte[] key = StringToByteArray("0123456789abcdef");
			byte[] plaintext = StringToByteArray(
			    "123456789abcdef0123456789abcdef012" +
				"3456789abcdef012345678");
			byte[] ciphertext = StringToByteArray(
			    "66a0949f8af7d6891f7f832ba833c00c89" +
			    "2ebe30143ce28740011ecf");
			CheckVector (key, plaintext, ciphertext);
		}
	}
}

