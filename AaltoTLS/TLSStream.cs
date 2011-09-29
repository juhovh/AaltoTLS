//
// AaltoTLS.TLSStream
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
using System.Net;
using System.Net.Security;
using System.Security.Permissions;
using System.Security.Cryptography.X509Certificates;

using AaltoTLS.Authentication;

namespace AaltoTLS
{
	public class TLSStream : AuthenticatedStream
	{
		private RemoteCertificateValidationCallback _validationCallback;
		private LocalCertificateSelectionCallback _selectionCallback;
		
		public TLSStream(Stream innerStream)
			: this(innerStream, false)
		{
		}
		
		public TLSStream(Stream innerStream, bool leaveInnerStreamOpen)
			: base(innerStream, leaveInnerStreamOpen)
		{
		}
		
		public TLSStream(Stream innerStream,
		                 bool leaveInnerStreamOpen,
		                 RemoteCertificateValidationCallback userCertificateValidationCallback)
			: base(innerStream, leaveInnerStreamOpen)
		{
			_validationCallback = userCertificateValidationCallback;
		}
		
		public TLSStream(Stream innerStream,
		                 bool leaveInnerStreamOpen,
		                 RemoteCertificateValidationCallback userCertificateValidationCallback,
		                 LocalCertificateSelectionCallback userCertificateSelectionCallback)
			: base(innerStream, leaveInnerStreamOpen)
		{
			_validationCallback = userCertificateValidationCallback;
			_selectionCallback = userCertificateSelectionCallback;
		}
		
		
		// Overridden Stream class properties
		
		public override bool CanRead {
			get { return InnerStream.CanRead; }
		}
		
		public override bool CanSeek {
			get { return false; }
		}
		
		public override bool CanTimeout {
			get { return InnerStream.CanTimeout; }
		}
		
		public override bool CanWrite {
			get { return InnerStream.CanWrite; }
		}
		
		public override long Length {
			get { return InnerStream.Length; }
		}
		
		public override long Position {
			get { return InnerStream.Position; }
			set { throw new NotSupportedException("Seeking in SslStream not supported"); }
		}
		
		public override int ReadTimeout {
			get { return InnerStream.ReadTimeout; }
			set { InnerStream.ReadTimeout = value; }
		}
		
		public override int WriteTimeout {
			get { return InnerStream.ReadTimeout; }
			set { InnerStream.ReadTimeout = value; }
		}
		
		
		// Overridden AuthenticatedStream class properties
		
		public override bool IsAuthenticated {
			// FIXME: Get real authentication status
			get { return false; }
		}
		
		public override bool IsEncrypted {
			// FIXME: Get real encryption status
			get { return false; }
		}
		
		public override bool IsMutuallyAuthenticated {
			// FIXME: Check that client certificate validated
			get { return false; }
		}
		
		public override bool IsServer {
			// FIXME: Get real endpoint status
			get { return false; }
		}
		
		public override bool IsSigned {
			// FIXME: Get real signature status
			get { return IsAuthenticated; }
		}
		
		
		// SslStream class properties
		
		public virtual bool CheckCertRevocationStatus {
			// FIXME: Check the certificate revocation status
			get { return true; }
		}
		
		public virtual CipherAlgorithmType CipherAlgorithm {
			// FIXME: Get real cipher algorithm type
			get { return CipherAlgorithmType.None; }
		}
		
		public virtual int CipherStrength {
			// FIXME: Get real cipher algorithm strength
			get { return 0; }
		}
		
		public virtual HashAlgorithmType HashAlgorithm {
			// FIXME: Get real hash algorithm type
			get { return HashAlgorithmType.None; }
		}
		
		public virtual int HashStrength {
			// FIXME: Get real hash algorithm strength
			get { return 0; }
		}
		
		public virtual ExchangeAlgorithmType KeyExchangeAlgorithm {
			// FIXME: Get real key exchange algorithm type
			get { return ExchangeAlgorithmType.None; }
		}
		
		public virtual int KeyExchangeStrength {
			// FIXME: Get real key exchange algorithm strength
			get { return 0; }
		}
		
		public virtual X509Certificate LocalCertificate {
			// FIXME: Get selected local certificate
			get { return null; }
		}
		
		public virtual X509Certificate RemoteCertificate {
			// FIXME: Get received remote certificate
			get { return null; }
		}
		
		public virtual SslProtocols SslProtocol {
			// FIXME: Get the selected SSL protocol version
			get { return SslProtocols.Default; }
		}
		
		
		
		// Overridden Stream class methods
		
		[HostProtectionAttribute(SecurityAction.LinkDemand, ExternalThreading = true)]
		public override IAsyncResult BeginRead(byte[] buffer,
		                                       int offset,
		                                       int count,
		                                       AsyncCallback asyncCallback,
		                                       Object asyncState)
		{
			// FIXME: Implement asynchronous read
			return null;
		}
		
		[HostProtectionAttribute(SecurityAction.LinkDemand, ExternalThreading = true)]
		public override IAsyncResult BeginWrite(byte[] buffer,
		                                        int offset,
		                                        int count,
		                                        AsyncCallback asyncCallback,
		                                        Object asyncState)
		{
			// FIXME: Implement asynchronous write
			return null;
		}
		
		public override int EndRead(IAsyncResult asyncResult)
		{
			// FIXME: Implement asynchronous read
			return 0;
		}
		
		public override void EndWrite(IAsyncResult asyncResult)
		{
			// FIXME: Implement asynchronous write
		}
		
		public override void Flush()
		{
			// FIXME: Flush all data in buffers
		}
		
		public override int Read(byte[] buffer,
		                         int offset,
		                         int count)
		{
			return EndRead(BeginRead(buffer, offset, count, null, null));
		}
		
		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException("Seeking in SslStream not supported");
		}
		
		public override void SetLength(long value)
		{
			InnerStream.SetLength(value);
		}
		
		public override void Write(byte[] buffer,
		                           int offset,
		                           int count)
		{
			EndWrite(BeginWrite(buffer, offset, count, null, null));
		}
		
		
		
		// Overridden AuthenticatedStream class methods
		
		protected override void Dispose(bool disposing)
		{
			// FIXME: Handle disposal correctly
		}
		
		
		
		// Overridden SslStream class methods
		
		public virtual void AuthenticateAsClient(string targetHost)
		{
			AuthenticateAsClient(targetHost, new X509CertificateCollection(), SslProtocols.Default, false);
		}
		
		public virtual void AuthenticateAsClient(string targetHost,
		                                         X509CertificateCollection clientCertificates,
		                                         SslProtocols enabledSslProtocols,
		                                         bool checkCertificateRevocation)
		{
			EndAuthenticateAsClient(BeginAuthenticateAsClient(targetHost,
			                                                  clientCertificates,
			                                                  enabledSslProtocols,
			                                                  checkCertificateRevocation,
			                                                  null, null));
		}
		
		public virtual void AuthenticateAsServer(X509Certificate serverCertificate)
		{
			AuthenticateAsServer(serverCertificate, false, SslProtocols.Default, false);
		}
		
		public virtual void AuthenticateAsServer(X509Certificate serverCertificate,
		                                         bool clientCertificateRequired,
		                                         SslProtocols enabledSslProtocols,
		                                         bool checkCertificateRevocation)
		{
			EndAuthenticateAsServer(BeginAuthenticateAsServer(serverCertificate,
			                                                  clientCertificateRequired,
			                                                  enabledSslProtocols,
			                                                  checkCertificateRevocation,
			                                                  null, null));
		}
		
		[HostProtectionAttribute(SecurityAction.LinkDemand, ExternalThreading = true)]
		public virtual IAsyncResult BeginAuthenticateAsClient(string targetHost,
		                                                      AsyncCallback asyncCallback,
		                                                      Object asyncState)
		{
			return BeginAuthenticateAsClient(targetHost,
			                                 new X509CertificateCollection(),
			                                 SslProtocols.Default,
			                                 false,
			                                 asyncCallback,
			                                 asyncState);
		}
		
		[HostProtectionAttribute(SecurityAction.LinkDemand, ExternalThreading = true)]
		public virtual IAsyncResult BeginAuthenticateAsClient(string targetHost,
		                                                      X509CertificateCollection clientCertificates,
		                                                      SslProtocols enabledSslProtocols,
		                                                      bool checkCertificateRevocation,
		                                                      AsyncCallback asyncCallback,
		                                                      Object asyncState)
		{
			// FIXME: Implement asynchronous client authentication
			return null;
		}
		
		[HostProtectionAttribute(SecurityAction.LinkDemand, ExternalThreading = true)]
		public virtual IAsyncResult BeginAuthenticateAsServer(X509Certificate serverCertificate,
		                                                      AsyncCallback asyncCallback,
		                                                      Object asyncState)
		{
			return BeginAuthenticateAsServer(serverCertificate,
			                                 false,
			                                 SslProtocols.Default,
			                                 false,
			                                 asyncCallback,
			                                 asyncState);
		}
		
		[HostProtectionAttribute(SecurityAction.LinkDemand, ExternalThreading = true)]
		public virtual IAsyncResult BeginAuthenticateAsServer(X509Certificate serverCertificate,
		                                                      bool clientCertificateRequired,
		                                                      SslProtocols enabledSslProtocols,
		                                                      bool checkCertificateRevocation,
		                                                      AsyncCallback asyncCallback,
		                                                      Object asyncState)
		{
			// FIXME: Implement asynchronous server authentication
			return null;
		}
		
		public virtual void EndAuthenticateAsClient(IAsyncResult asyncResult)
		{
			// FIXME: Implement asynchronous client authentication
		}
		
		public virtual void EndAuthenticateAsServer(IAsyncResult asyncResult)
		{
			// FIXME: Implement asynchronous server authentication
		}
		
		public void Write(byte[] buffer)
		{
			Write(buffer, 0, buffer.Length);
		}
		
		
		
		public static bool DefaultCertificateValidationCallback(object sender,
		                                                        X509Certificate certificate,
		                                                        X509Chain chain,
		                                                        SslPolicyErrors sslPolicyErrors)
		{
			// If no errors found, accept the certificate
			return (sslPolicyErrors == SslPolicyErrors.None);
		}
		
		public static X509Certificate DefaultCertificateSelectionCallback(object sender,
		                                                                  string targetHost,
		                                                                  X509CertificateCollection localCertificates,
		                                                                  X509Certificate remoteCertificate,
		                                                                  string[] acceptableIssuers)
		{
			if (localCertificates == null || localCertificates.Count == 0) {
				return null;
			}
			
			if (acceptableIssuers != null && acceptableIssuers.Length > 0) {
				foreach (X509Certificate certificate in localCertificates) {
					// Return certificate from acceptable issuer if found a match
					if (Array.IndexOf(acceptableIssuers, certificate.Issuer) != -1)
						return certificate;
				}
			}
			
			// Return the first client certificate
			return localCertificates[0];
		}
	}
}

