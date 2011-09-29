//
// AaltoTLS.PluginInterface.KeyExchangeAlgorithm
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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AaltoTLS.PluginInterface
{
	public abstract class KeyExchangeAlgorithm
	{
		// Returns the OID for compatible certificate or null
		public abstract string CertificateKeyAlgorithm { get; }
		
		// Returns true if this version is supported, otherwise false
		public abstract bool SupportsProtocolVersion(ProtocolVersion version);
		
		// Returns the server key exchange message as a byte array
		public abstract byte[] GetServerKeys(ProtocolVersion version);
		// Returns the server key exchange signature as a byte array
		public abstract byte[] ProcessServerKeys(ProtocolVersion version, byte[] data);

		// Returns the client key exchange message as a byte array
		public abstract byte[] GetClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePublicKey publicKey);
		public abstract void ProcessClientKeys(ProtocolVersion version, ProtocolVersion clientVersion, CertificatePrivateKey privateKey, byte[] data);
		
		// Returns the resulting master secret, either GetClientKeys or
		// ProcessClientKeys needs to be called before calling this method
		public abstract byte[] GetMasterSecret(PseudoRandomFunction prf, byte[] seed);
	}
}
