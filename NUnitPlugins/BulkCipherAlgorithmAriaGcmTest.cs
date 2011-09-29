//
// BulkCipherAlgorithmAriaGcmTest
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

namespace ARIACipherSuitePlugin
{
	[TestFixture]
	public class BulkCipherAlgorithmAriaGcmTest
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
			BulkCipherAlgorithmAriaGcm cipher = new BulkCipherAlgorithmAriaGcm(key.Length*8, tag.Length*8);
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
		public void Vector ()
		{
			/* Test vector from draft-nsri-avt-aria-srtp-00 */
			byte[] key = StringToByteArray("e91e5e75da65554a48181f3846349562");
			byte[] plaintext = StringToByteArray(
			    "f57af5fd4ae19562976ec57a5a7ad55a" +
				"5af5c5e5c5fdf5c55ad57a4a7272d572" +
				"62e9729566ed66e97ac54a4a5a7ad5e1" +
				"5ae5fdd5fd5ac5d56ae56ad5c572d54a" +
				"e54ac55a956afd6aed5a4ac562957a95" +
				"16991691d572fd14e97ae962ed7a9f4a" +
				"955af572e162f57a956666e17ae1f54a" +
				"95f566d54a66e16e4afd6a9f7ae1c5c5" +
				"5ae5d56afde916c5e94a6ec56695e14a" +
				"fde1148416e94ad57ac5146ed59d1cc5");
			byte[] additional = StringToByteArray("8008315ebf2e6fe020e8f5eb");
			byte[] nonce = StringToByteArray("000020e8f5eb00000000315e");
			byte[] ciphertext = StringToByteArray(
				"4d8a9a0675550c704b17d8c9ddc81a5c" +
				"d6f7da34f2fe1b3db7cb3dfb9697102e" +
				"a0f3c1fc2dbc873d44bceeae8e444297" +
				"4ba21ff6789d3272613fb9631a7cf3f1" +
				"4bacbeb421633a90ffbe58c2fa6bdca5" +
				"34f10d0de0502ce1d531b6336e588782" +
				"78531e5c22bc6c85bbd784d78d9e680a" +
				"a19031aaf89101d669d7a3965c1f7e16" +
				"229d7463e0535f4e253f5d18187d40b8" +
				"ae0f564bd970b5e7e2adfb211e89a953");
			byte[] tag = StringToByteArray("5abace3f37f5a736f4be984b");
			CheckVector (key, plaintext, additional, nonce, ciphertext, tag);
		}
	}
}
