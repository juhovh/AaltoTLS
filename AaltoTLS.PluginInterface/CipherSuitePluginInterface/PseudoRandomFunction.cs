//
// AaltoTLS.PluginInterface.PseudoRandomFunction
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
using System.Text;
using System.Security.Cryptography;

namespace AaltoTLS.PluginInterface
{
	public abstract class PseudoRandomFunction
	{
		// Returns true if this version is supported, otherwise false
		public abstract bool SupportsProtocolVersion(ProtocolVersion version);
		
		// Returns the hasher used over all handshake messages in Finished message
		// and the length of pseudorandom bytes actually included in Finished,
		// the secret parameter includes the master secret, only used for SSLv3
		public abstract HashAlgorithm CreateVerifyHashAlgorithm(byte[] secret);
		public abstract int VerifyDataLength { get; }

		// The secret parameter is the master secret, seed is usually label + randoms
		public abstract DeriveBytes CreateDeriveBytes(byte[] secret, byte[] seed);
		
		// Helper function to concatenate label and seed, overridden in SSLv3
		public virtual DeriveBytes CreateDeriveBytes(byte[] secret, string label, byte[] seed)
		{
			if (label != null) {
				/* Construct the final seed from (label + seed) */
				byte[] labelBytes = Encoding.ASCII.GetBytes(label);
				byte[] finalSeed = new byte[labelBytes.Length + seed.Length];

				Buffer.BlockCopy(labelBytes, 0, finalSeed, 0, labelBytes.Length);
				Buffer.BlockCopy(seed, 0, finalSeed, labelBytes.Length, seed.Length);

				return CreateDeriveBytes(secret, finalSeed);
			} else {
				return CreateDeriveBytes(secret, seed);
			}
		}
		
		// Helper function for getting certain amount of pseudorandom bytes
		public byte[] GetBytes(byte[] secret, string label, byte[] seed, int count)
		{
			return CreateDeriveBytes(secret, label, seed).GetBytes(count);
		}
	}
}
