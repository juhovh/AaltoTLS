//
// AaltoTLS.HandshakeLayer.Protocol.HandshakeServerHello
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
using AaltoTLS.PluginInterface;
using AaltoTLS.Alerts;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HandshakeServerHello: HandshakeMessage
	{
		public ProtocolVersion  ServerVersion;
		public HandshakeRandom  Random;
		public byte[]           SessionID;
		public UInt16           CipherSuite;
		public Byte             CompressionMethod;
		
		public readonly List<HelloExtension>  Extensions;

		internal HandshakeServerHello() : this(ProtocolVersion.NULL) {}
		
		public HandshakeServerHello(ProtocolVersion version) : base(HandshakeMessageType.ServerHello, version)
		{
			ServerVersion      = version;
			Random             = new HandshakeRandom();
			SessionID          = new byte[0];
			CipherSuite        = 0x0000;
			CompressionMethod  = 0x00;
			Extensions         = new List<HelloExtension>();
		}

		protected override byte[] EncodeDataBytes(ProtocolVersion ver)
		{
			MemoryStream memStream = new MemoryStream();
			HandshakeStream stream = new HandshakeStream(memStream);

			stream.WriteUInt8(ServerVersion.Major);
			stream.WriteUInt8(ServerVersion.Minor);

			stream.WriteBytes(Random.GetBytes());

			stream.WriteUInt8((Byte) SessionID.Length);
			stream.WriteBytes(SessionID);

			stream.WriteUInt16(CipherSuite);
			stream.WriteUInt8(CompressionMethod);
			
			if (Extensions.Count > 0) {
				int length = 0;
				foreach (HelloExtension ext in Extensions) {
					if (!ext.SupportsProtocolVersion(ServerVersion))
						continue;
					length += 4 + ext.Data.Length;
				}
				stream.WriteUInt16((UInt16) length);
				foreach (HelloExtension ext in Extensions) {
					if (!ext.SupportsProtocolVersion(ServerVersion))
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
			MemoryStream memStream = new MemoryStream(data);
			HandshakeStream stream = new HandshakeStream(memStream);

			byte major = stream.ReadUInt8();
			byte minor = stream.ReadUInt8();
			ServerVersion = new ProtocolVersion(major, minor);

			byte[] randomBytes = stream.ReadBytes(32);
			Random = new HandshakeRandom(randomBytes);

			int idLength = (int) stream.ReadUInt8();
			SessionID = stream.ReadBytes(idLength);

			CipherSuite = stream.ReadUInt16();
			CompressionMethod = stream.ReadUInt8();
			
			byte[] extensionList = new byte[0];
			if (!stream.EndOfStream && ServerVersion.HasExtensions) {
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
					                         "ServerHello extension data length too large: " + extensionDataLength);
				}

				byte[] extensionData = new byte[extensionDataLength];
				Buffer.BlockCopy(extensionList, pos, extensionData, 0, extensionData.Length);
				pos += extensionData.Length;

				Extensions.Add(new HelloExtension(extensionType, extensionData));
			}
		}
	}
}


