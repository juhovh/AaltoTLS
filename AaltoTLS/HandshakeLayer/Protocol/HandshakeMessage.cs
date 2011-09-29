//
// AaltoTLS.HandshakeLayer.Protocol.HandshakeMessage
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
using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HandshakeMessage
	{
		public readonly HandshakeMessageType Type;
		private ProtocolVersion _version;
		private byte[] _data;
		
		public byte[] Data
		{
			get { return EncodeDataBytes(_version); }
		}
		
		public HandshakeMessage(HandshakeMessageType type, ProtocolVersion version)
		{
			Type = type;
			_version = version;
			_data = new byte[0];
		}
		
		public HandshakeMessage(HandshakeMessageType type, ProtocolVersion version, byte[] data)
		{
			if (data == null) {
				throw new AlertException(AlertDescription.InternalError,
				                         "Trying to create HandshakeMessage with null data");
			}
			
			Type = type;
			_version = version;
			_data = (byte[])data.Clone();
		}

		public byte[] Encode()
		{
			MemoryStream memStream = new MemoryStream();
			HandshakeStream stream = new HandshakeStream(memStream);
			
			byte[] dataBytes;
			try {
				dataBytes = EncodeDataBytes(_version);
			} catch (AlertException ae) {
				throw ae;
			} catch (Exception e) {
				throw new AlertException(AlertDescription.InternalError, e.Message);
			}

			stream.WriteUInt8((byte) Type);
			stream.WriteUInt24((UInt32) dataBytes.Length);
			stream.WriteBytes(dataBytes);

			return memStream.ToArray();
		}

		public void Decode(byte[] data)
		{
			MemoryStream memStream = new MemoryStream(data);
			HandshakeStream stream = new HandshakeStream(memStream);

			int type = (int) stream.ReadUInt8();
			if (type != (int) Type) {
				throw new AlertException(AlertDescription.InternalError, "Incorrect message type");
			}

			int fragmentLength = (int) stream.ReadUInt24();
			byte[] fragment = stream.ReadBytes(fragmentLength);
			
			try {
				DecodeDataBytes(_version, fragment);
			} catch (AlertException ae) {
				throw ae;
			} catch (Exception e) {
				throw new AlertException(AlertDescription.InternalError, e.Message);
			}
		}

		protected virtual byte[] EncodeDataBytes(ProtocolVersion version)
		{
			return _data;
		}

		protected virtual void DecodeDataBytes(ProtocolVersion version, byte[] data)
		{
			_data = data;
		}

		public static HandshakeMessage GetInstance(ProtocolVersion version, byte[] data)
		{
			HandshakeMessage ret = null;

			switch ((HandshakeMessageType) data[0]) {
			case HandshakeMessageType.HelloRequest:
				ret = new HandshakeMessage(HandshakeMessageType.HelloRequest, version);
				break;
			case HandshakeMessageType.ClientHello:
				ret = new HandshakeClientHello();
				break;
			case HandshakeMessageType.ServerHello:
				ret = new HandshakeServerHello();
				break;
			case HandshakeMessageType.HelloVerifyRequest:
				ret = new HandshakeMessage(HandshakeMessageType.HelloVerifyRequest, version);
				break;
			case HandshakeMessageType.NewSessionTicket:
				ret = new HandshakeMessage(HandshakeMessageType.NewSessionTicket, version);
				break;
			case HandshakeMessageType.Certificate:
				ret = new HandshakeCertificate(version);
				break;
			case HandshakeMessageType.ServerKeyExchange:
				ret = new HandshakeMessage(HandshakeMessageType.ServerKeyExchange, version);
				break;
			case HandshakeMessageType.CertificateRequest:
				ret = new HandshakeCertificateRequest(version);
				break;
			case HandshakeMessageType.ServerHelloDone:
				ret = new HandshakeMessage(HandshakeMessageType.ServerHelloDone, version);
				break;
			case HandshakeMessageType.CertificateVerify:
				ret = new HandshakeMessage(HandshakeMessageType.CertificateVerify, version);
				break;
			case HandshakeMessageType.ClientKeyExchange:
				ret = new HandshakeMessage(HandshakeMessageType.ClientKeyExchange, version);
				break;
			case HandshakeMessageType.Finished:
				ret = new HandshakeMessage(HandshakeMessageType.Finished, version);
				break;
			}

			if (ret != null) {
				ret.Decode(data);
				return ret;
			}
			return null;
		}
	}
}
