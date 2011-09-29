//
// AaltoTLS.SecurityParameters
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
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AaltoTLS.PluginInterface;

namespace AaltoTLS
{
	// TODO: Should include client cipher suites and extensions to help in selection
	public delegate int ServerCertificateSelectionCallback(CipherSuite cipherSuite, X509CertificateCollection[] serverCertificates);
	
	public delegate bool ServerCertificateValidationCallback(X509CertificateCollection certificates);
	
	// TODO: Should include supported hash algorithms and possibly other information, what?
	public delegate int ClientCertificateSelectionCallback(X509CertificateCollection[] clientCertificates, X509CertificateCollection serverCertificate);
	
	public class SecurityParameters
	{
		private List<X509CertificateCollection>  _availableCertificates;
		private List<CertificatePrivateKey>      _availablePrivateKeys;
		
		public ProtocolVersion  MinimumVersion;
		public ProtocolVersion  MaximumVersion;
		public readonly List<UInt16>     CipherSuiteIDs;
		public readonly List<Byte>       CompressionIDs;
		
		// Callbacks used by clients, null means default
		public ServerCertificateValidationCallback ServerCertificateValidationCallback;
		public ClientCertificateSelectionCallback  ClientCertificateSelectionCallback;
		
		// Callbacks used by servers, null means default
		public ServerCertificateSelectionCallback  ServerCertificateSelectionCallback;
		
		// Client certificate parameters, ignored if client
		public readonly List<Byte>   ClientCertificateTypes;
		public readonly List<string> ClientCertificateAuthorities;
		
		
		public X509CertificateCollection[] AvailableCertificates
		{
			get { return _availableCertificates.ToArray(); }
		}
		
		public CertificatePrivateKey[] AvailablePrivateKeys
		{
			get { return _availablePrivateKeys.ToArray(); }
		}
		
		public SecurityParameters()
		{
			_availableCertificates = new List<X509CertificateCollection>();
			_availablePrivateKeys = new List<CertificatePrivateKey>();
			
			MinimumVersion = ProtocolVersion.SSL3_0;
			MaximumVersion = ProtocolVersion.TLS1_2;

			CipherSuiteIDs = new List<UInt16>();
			//CipherSuiteIDs.Add(0x002F); // TLS_RSA_WITH_AES_128_CBC_SHA
			//CipherSuiteIDs.Add(0x0033); // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			
			CompressionIDs = new List<Byte>();
			CompressionIDs.Add(0x00);
			
			ClientCertificateTypes = new List<Byte>();
			ClientCertificateAuthorities = new List<string>();
		}
		
		public void AddCertificate(X509CertificateCollection certificate, CertificatePrivateKey privateKey)
		{
			if (certificate == null)
				throw new ArgumentNullException("certificate");
			if (privateKey == null)
				throw new ArgumentNullException("privateKey");
			if (certificate.Count == 0)
				throw new ArgumentException("certificate");
			
			_availableCertificates.Add(certificate);
			_availablePrivateKeys.Add(privateKey);
		}
	}
}

