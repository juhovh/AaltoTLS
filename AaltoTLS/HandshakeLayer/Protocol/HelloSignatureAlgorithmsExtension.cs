//
// AaltoTLS.HandshakeLayer.Protocol.HelloSignatureAlgorithmsExtension
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
using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;

namespace AaltoTLS.HandshakeLayer.Protocol
{
	public class HelloSignatureAlgorithmsExtension : HelloExtension
	{
		public readonly List<UInt16> SupportedSignatureAlgorithms;
		
		public HelloSignatureAlgorithmsExtension()
			: base(HelloExtensionType.SignatureAlgorithms)
		{
			SupportedSignatureAlgorithms = new List<UInt16>();
		}
		
		public HelloSignatureAlgorithmsExtension(UInt16[] supported)
			: base(HelloExtensionType.SignatureAlgorithms)
		{
			SupportedSignatureAlgorithms = new List<UInt16>(supported);
		}
		
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return version.HasSelectableSighash;
		}
		
		protected override byte[] EncodeDataBytes()
		{
			int count = SupportedSignatureAlgorithms.Count;
			
			byte[] data = new byte[2+2*count];
			data[0] = (byte)((2*count)>>8);
			data[1] = (byte)(2*count);
			for (int i=0; i<count; i++) {
				data[2+i*2] = (byte)(SupportedSignatureAlgorithms[i]>>8);
				data[2+i*2+1] = (byte)(SupportedSignatureAlgorithms[i]);
			}
			return data;
		}
		
		protected override void DecodeDataBytes(byte[] data)
		{
			if (data.Length < 2 || (data.Length % 2) != 0)  {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "SignatureAlgorithms extension data length invalid: " + data.Length);
			}
			int len = (data[0] << 8) | data[1];
			if (len != data.Length-2) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "SignatureAlgorithms extension data invalid");
			}
			for (int i=0; i<len/2; i++) {
				UInt16 sighash = (UInt16)((data[2+i*2] << 8) | data[2+i*2]);
				SupportedSignatureAlgorithms.Add(sighash);
			}
		}
	}
}