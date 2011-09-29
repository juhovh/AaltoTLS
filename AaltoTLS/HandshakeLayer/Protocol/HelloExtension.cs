//
// AaltoTLS.HandshakeLayer.Protocol.HelloExtension
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
using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HelloExtension
	{
		public readonly UInt16  Type;
		private byte[] _data;
		
		public byte[] Data
		{
			get { return EncodeDataBytes(); }
			set { DecodeDataBytes(value); }
		}
		
		protected HelloExtension(HelloExtensionType type)
			: this((UInt16) type) {}
		
		public HelloExtension(UInt16 type)
		{
			Type = type;
			_data = new byte[0];
		}

		public HelloExtension(UInt16 type, byte[] data)
		{
			if (data == null) {
				throw new AlertException(AlertDescription.InternalError,
				                         "Trying to create HandshakeExtension with null data");
			}
			
			Type = type;
			Data = data;
		}
		
		public virtual bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return version.HasExtensions;
		}
			
		protected virtual byte[] EncodeDataBytes()
		{
			return _data;
		}

		protected virtual void DecodeDataBytes(byte[] data)
		{
			_data = (byte[])data.Clone();
		}
	}
}
