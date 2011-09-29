//
// AaltoTLS.HandshakeLayer.Protocol.HandshakeCertificate
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
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HandshakeCertificate: HandshakeMessage
	{
		public readonly X509CertificateCollection  CertificateList;

		public HandshakeCertificate(ProtocolVersion version) : base(HandshakeMessageType.Certificate, version)
		{
			CertificateList = new X509CertificateCollection();
		}

		protected override byte[] EncodeDataBytes(ProtocolVersion version)
		{
			int certsLength = 0;
			foreach (X509Certificate cert in CertificateList) {
				certsLength += 3;
				certsLength += cert.GetRawCertData().Length;
			}

			MemoryStream memStream = new MemoryStream();
			HandshakeStream stream = new HandshakeStream(memStream);

			stream.WriteUInt24((UInt32) certsLength);
			foreach (X509Certificate cert in CertificateList) {
				byte[] certBytes = cert.GetRawCertData();

				stream.WriteUInt24((UInt32) certBytes.Length);
				stream.WriteBytes(certBytes);
			}

			return memStream.ToArray();
		}

		protected override void DecodeDataBytes(ProtocolVersion version, byte[] data)
		{
			CertificateList.Clear();

			MemoryStream memStream = new MemoryStream(data);
			HandshakeStream stream = new HandshakeStream(memStream);
			int certsLength = (int) stream.ReadUInt24();

			int readBytes = 0;
			while (readBytes<certsLength) {
				int certLength = (int) stream.ReadUInt24();
				byte[] certBytes = stream.ReadBytes(certLength);
				readBytes += 3+certLength;

				CertificateList.Add(new X509Certificate(certBytes));
			}
			if (readBytes != certsLength) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Certificate total length doesn't match contents");
			}
			stream.ConfirmEndOfStream();
		}
	}
}
