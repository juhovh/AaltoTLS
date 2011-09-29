//
// AaltoTLS.HandshakeLayer.TLSHandshakePacketizer
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

using AaltoTLS.RecordLayer;
using AaltoTLS.PluginInterface;
using AaltoTLS.HandshakeLayer.Protocol;

namespace AaltoTLS.HandshakeLayer
{
	public class TLSHandshakePacketizer : IHandshakePacketizer
	{
		private MemoryStream _inputStream = new MemoryStream();
		private int _inputtedBytes;
		
		public Record[] ProcessHandshakeMessages(ProtocolVersion version,
		                                         HandshakeMessage[] messages,
		                                         int maxFragmentLength)
		{
			List<Record> records = new List<Record>();
			
			// Write all handshake data to memory stream
			MemoryStream memStream = new MemoryStream();
			for (int i=0; i<messages.Length; i++) {
				byte[] msgBytes = messages[i].Encode();
				memStream.Write(msgBytes, 0, msgBytes.Length);
			}
			
			// Read handshake data from memory stream one at a time
			memStream.Position = 0;
			while (memStream.Position < memStream.Length) {
				long fragmentLength = Math.Min(memStream.Length-memStream.Position, maxFragmentLength);
				byte[] fragment = new byte[fragmentLength];
				memStream.Read(fragment, 0, fragment.Length);
				Record record = new Record(RecordType.Handshake, version);
				record.Fragment = fragment;
				records.Add(record);
			}
			
			return records.ToArray();
		}
		
		public Record[] ProcessOutputData(ProtocolVersion version, byte type, byte[] data, int maxFragmentLength)
		{
			List<Record> records = new List<Record>();
			
			// Read handshake data from memory stream one at a time
			MemoryStream memStream = new MemoryStream(data);
			while (memStream.Position < memStream.Length) {
				long fragmentLength = Math.Min(memStream.Length-memStream.Position, maxFragmentLength);
				byte[] fragment = new byte[fragmentLength];
				memStream.Read(fragment, 0, fragment.Length);
				Record record = new Record(type, version);
				record.Fragment = fragment;
				records.Add(record);
			}
			
			return records.ToArray();
		}
		
		public HandshakeMessage[] ProcessHandshakeRecord(ProtocolVersion version,
		                                                 Record record)
		{
			List<HandshakeMessage> ret = new List<HandshakeMessage>();
			
			// Write record to input stream and attempt to parse a handshake message
			_inputStream.Write(record.Fragment, 0, record.Fragment.Length);
			while (_inputStream.Length-_inputtedBytes >= 4) {
				byte[] inputBuffer = _inputStream.GetBuffer();
				
				int dataLength = (inputBuffer[_inputtedBytes+1] << 16) |
				                 (inputBuffer[_inputtedBytes+2] << 8)  |
				                  inputBuffer[_inputtedBytes+3];
				
				// Check that if we have enough data to read message now
				if (4+dataLength > _inputStream.Length-_inputtedBytes)
					break;
				
				byte[] msgData = new byte[4+dataLength];
				long writePosition = _inputStream.Position;
				
				// Read message data from inputStream
				_inputStream.Position = _inputtedBytes;
				_inputStream.Read(msgData, 0, msgData.Length);
				_inputStream.Position = writePosition;
				_inputtedBytes += msgData.Length;
				
				// Add resulting handshake message to the results
				ret.Add(HandshakeMessage.GetInstance(version, msgData));
			}
			
			if (_inputtedBytes == _inputStream.Length) {
				// Reset stream to save memory
				_inputStream.Position = 0;
				_inputStream.SetLength(0);
				_inputtedBytes = 0;
			}
			
			return ret.ToArray();
		}
	}
}

