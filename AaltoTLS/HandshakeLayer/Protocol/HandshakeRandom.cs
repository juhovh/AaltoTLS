//
// AaltoTLS.HandshakeLayer.Protocol.HandshakeRandom
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
using System.Security.Cryptography;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HandshakeRandom
	{
		public readonly UInt32  gmt_unix_time;
		public readonly byte[]  random_bytes;

		public HandshakeRandom()
		{
			TimeSpan ts = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0));
			gmt_unix_time = (UInt32) ts.TotalSeconds;

			RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
			byte[] randomBytes = new byte[28];
			rngCsp.GetBytes(randomBytes);
			random_bytes = randomBytes;
		}

		public HandshakeRandom(byte[] data)
		{
			UInt32 unix_time = 0;
			unix_time |= ((UInt32) data[0]) << 24;
			unix_time |= ((UInt32) data[1]) << 16;
			unix_time |= ((UInt32) data[2]) << 8;
			unix_time |= (UInt32) data[3];
			this.gmt_unix_time = unix_time;

			byte[] randomBytes = new byte[28];
			Array.Copy(data, 4, randomBytes, 0, 28);
			this.random_bytes = randomBytes;
		}

		public byte[] GetBytes()
		{
			byte[] data = new byte[32];
			data[0] = (byte) ((gmt_unix_time >> 24) & 0xff);
			data[1] = (byte) ((gmt_unix_time >> 16) & 0xff);
			data[2] = (byte) ((gmt_unix_time >>  8) & 0xff);
			data[3] = (byte) (gmt_unix_time & 0xff);
			Array.Copy(random_bytes, 0, data, 4, 28);
			return data;
		}
	}
}
