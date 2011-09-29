//
// AaltoTLS.HandshakeLayer.Protocol.HandshakeClientHello
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
using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HandshakeClientHello : HandshakeMessage
	{
		public ProtocolVersion           ClientVersion;
		public HandshakeRandom           Random;
		public byte[]                    SessionID;
		public byte[]                    Cookie; // Only used in DTLS
		public readonly List<UInt16>     CipherSuites;
		public readonly List<Byte>       CompressionMethods;
		public readonly List<HelloExtension>  Extensions;

		internal HandshakeClientHello() : this(ProtocolVersion.NULL) {}
		
		public HandshakeClientHello(ProtocolVersion version) : base(HandshakeMessageType.ClientHello, version)
		{
			ClientVersion       = version;
			Random              = new HandshakeRandom();
			SessionID           = new byte[0];
			Cookie              = new byte[0];
			CipherSuites        = new List<UInt16>();
			CompressionMethods  = new List<Byte>();
			Extensions          = new List<HelloExtension>();
		}
		
		public override string ToString()
		{
			string ret = "";

			ret += "ClientHello: " + ClientVersion.ToString() + "\n";
			ret += "Cipher suites: " + CipherSuites.Count + "\n";
			ret += "Compression methods: " + CompressionMethods.Count;

			return ret;
		}

		protected override byte[] EncodeDataBytes(ProtocolVersion ver)
		{
			if (CipherSuites.Count == 0 || CompressionMethods.Count == 0) {
				throw new Exception("No cipher suites or compression methods defined");
			}

			MemoryStream memStream = new MemoryStream();
			HandshakeStream stream = new HandshakeStream(memStream);

			stream.WriteUInt8(ClientVersion.Major);
			stream.WriteUInt8(ClientVersion.Minor);
			stream.WriteBytes(Random.GetBytes());
			stream.WriteUInt8((Byte) SessionID.Length);
			stream.WriteBytes(SessionID);
			if (ClientVersion.IsUsingDatagrams) {
				stream.WriteUInt8((Byte) Cookie.Length);
				stream.WriteBytes(Cookie);
			}

			stream.WriteUInt16((UInt16) (2*CipherSuites.Count));
			foreach (UInt16 cipher in CipherSuites) {
				stream.WriteUInt16(cipher);
			}

			stream.WriteUInt8((Byte) CompressionMethods.Count);
			foreach (Byte compression in CompressionMethods) {
				stream.WriteUInt8(compression);
			}

			if (Extensions.Count > 0) {
				int length = 0;
				foreach (HelloExtension ext in Extensions) {
					if (!ext.SupportsProtocolVersion(ClientVersion))
						continue;
					length += 4 + ext.Data.Length;
				}
				stream.WriteUInt16((UInt16) length);
				foreach (HelloExtension ext in Extensions) {
					if (!ext.SupportsProtocolVersion(ClientVersion))
						continue;
					
					UInt16 type = ext.Type;
					byte[] data = ext.Data;
					
					stream.WriteUInt16(type);
					stream.WriteUInt16((UInt16) data.Length);
					stream.WriteBytes(data);
				}
			}

			return memStream.ToArray();
		}

		protected override void DecodeDataBytes(ProtocolVersion ver, byte[] data)
		{
			CipherSuites.Clear();
			CompressionMethods.Clear();

			MemoryStream memStream = new MemoryStream(data);
			HandshakeStream stream = new HandshakeStream(memStream);

			byte major = stream.ReadUInt8();
			byte minor = stream.ReadUInt8();
			ClientVersion = new ProtocolVersion(major, minor);

			byte[] randomBytes = stream.ReadBytes(32);
			Random = new HandshakeRandom(randomBytes);

			int idLength = (int) stream.ReadUInt8();
			SessionID = stream.ReadBytes(idLength);
			
			if (ClientVersion.IsUsingDatagrams) {
				int cookieLength = (int) stream.ReadUInt8();
				Cookie = stream.ReadBytes(cookieLength);
			}

			int cipherLength = (int) stream.ReadUInt16();
			for (int i=0; i<cipherLength; i+=2) {
				CipherSuites.Add(stream.ReadUInt16());
			}

			int compressionLength = (int) stream.ReadUInt8();
			for (int i=0; i<compressionLength; i++) {
				CompressionMethods.Add(stream.ReadUInt8());
			}

			byte[] extensionList = new byte[0];
			if (!stream.EndOfStream && ClientVersion.HasExtensions) {
				UInt16 extensionListLength = stream.ReadUInt16();
				extensionList = stream.ReadBytes(extensionListLength);
			}
			stream.ConfirmEndOfStream();
			
			int pos = 0;
			while (pos+4 <= extensionList.Length) {
				UInt16 extensionType = (UInt16) ((extensionList[pos] << 8) | extensionList[pos+1]);
				UInt16 extensionDataLength = (UInt16) ((extensionList[pos+2] << 8) | extensionList[pos+3]);
				pos += 4;
				
				if (pos+extensionDataLength > extensionList.Length) {
					throw new AlertException(AlertDescription.IllegalParameter,
					                         "ClientHello extension data length too large: " + extensionDataLength);
				}

				byte[] extensionData = new byte[extensionDataLength];
				Buffer.BlockCopy(extensionList, pos, extensionData, 0, extensionData.Length);
				pos += extensionData.Length;

				Extensions.Add(new HelloExtension(extensionType, extensionData));
			}
		}
	}
}
