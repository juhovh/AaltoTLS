//
// AaltoTLS.HandshakeLayer.Protocol.HandshakeCertificateRequest
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
using System.Collections.Generic;
using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HandshakeCertificateRequest: HandshakeMessage
	{
		public readonly List<Byte>    CertificateTypes;
		public readonly List<UInt16>  SignatureAndHashAlgorithms;
		public readonly List<string>  CertificateAuthorities;

		public HandshakeCertificateRequest(ProtocolVersion version) : base(HandshakeMessageType.CertificateRequest, version)
		{
			CertificateTypes = new List<byte>();
			SignatureAndHashAlgorithms = new List<ushort>();
			CertificateAuthorities = new List<string>();
		}

		protected override byte[] EncodeDataBytes(ProtocolVersion version)
		{
			int typesLength = 0;
			if (CertificateTypes.Count > 255) {
				throw new Exception("Number of certificate types too large: " + CertificateTypes.Count);
			} else {
				typesLength = CertificateTypes.Count;
			}
			
			int sighashLength = 0;
			if (version.HasSelectableSighash) {
				if (SignatureAndHashAlgorithms.Count > 65535) {
					throw new Exception("Number of sighash values too large: " + SignatureAndHashAlgorithms.Count);
				} else {
					sighashLength = 2*SignatureAndHashAlgorithms.Count;
				}
			}

			int authsLength = 0;
			foreach (string name in CertificateAuthorities) {
				// TODO: Should support punycode as well?
				authsLength += 2;
				authsLength += Encoding.ASCII.GetBytes(name).Length;
				if (authsLength > 65535) {
					throw new Exception("Certificate authorities length too large");
				}
			}

			MemoryStream memStream = new MemoryStream();
			HandshakeStream stream = new HandshakeStream(memStream);

			stream.WriteUInt8((byte) typesLength);
			foreach (byte type in CertificateTypes) {
				stream.WriteUInt8(type);
			}
			
			if (version.HasSelectableSighash) {
				stream.WriteUInt16((UInt16) sighashLength);
				foreach (UInt16 sighash in SignatureAndHashAlgorithms) {
					stream.WriteUInt16(sighash);
				}
			}
			
			stream.WriteUInt16((UInt16) authsLength);
			foreach (string name in CertificateAuthorities) {
				// TODO: Should support punycode as well?
				int nameLen = Encoding.ASCII.GetBytes(name).Length;
				stream.WriteUInt16((UInt16) nameLen);
				stream.WriteBytes(Encoding.ASCII.GetBytes(name));
			}

			return memStream.ToArray();
		}

		protected override void DecodeDataBytes(ProtocolVersion version, byte[] data)
		{
			CertificateTypes.Clear();
			CertificateAuthorities.Clear();
			
			MemoryStream memStream = new MemoryStream(data);
			HandshakeStream stream = new HandshakeStream(memStream);
			
			int typesLength = stream.ReadUInt8();
			for (int i=0; i<typesLength; i++) {
				CertificateTypes.Add(stream.ReadUInt8());
			}
			
			if (version.HasSelectableSighash) {
				int sighashLength = stream.ReadUInt16();
				if ((sighashLength%2) != 0) {
					throw new AlertException(AlertDescription.IllegalParameter,
					                         "SianatureAndHashAlgorithms length invalid: " + sighashLength);
				}
				
				byte[] sighashData = stream.ReadBytes(sighashLength);
				for (int i=0; i<sighashLength; i+=2) {
					SignatureAndHashAlgorithms.Add((UInt16)((sighashData[i] << 8) | sighashData[i+1]));
				}
			}
			
			int authsLength = stream.ReadUInt16();
			byte[] authData = stream.ReadBytes(authsLength);
			stream.ConfirmEndOfStream();
			
			int position=0;
			while (position < authData.Length) {
				int authLength = (authData[position] << 8) | authData[position+1];
				position += 2;
				
				if (position > authData.Length) {
					throw new AlertException(AlertDescription.IllegalParameter,
					                         "Authorities total length doesn't match contents");
				}
				
				string name = Encoding.ASCII.GetString(authData, position, authLength);
				position += authLength;
				
				CertificateAuthorities.Add(name);
			}
		}
	}
}
