//
// AaltoTLS.HandshakeLayer.Protocol.HandshakeStream
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

namespace AaltoTLS.HandshakeLayer.Protocol
{
	class HandshakeStream
	{
		private BinaryReader _reader;
		private BinaryWriter _writer;

		public HandshakeStream(Stream stream)
		{
			_reader = new BinaryReader(stream);
			_writer = new BinaryWriter(stream);
		}
		
		public bool EndOfStream
		{
				get { return (_reader.BaseStream.Length == _reader.BaseStream.Position); }
		}
		
		public void ConfirmEndOfStream()
		{
			if (_reader.BaseStream.Length != _reader.BaseStream.Position) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "HandshakeStream has unexpected data after end of packet");
			}
		}

		public Byte ReadUInt8()
		{
			Byte ret;
			try {
				ret = _reader.ReadByte();
			} catch (Exception) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Error reading UInt8 in HandshakeStream");
			}
			return ret;
		}

		public UInt16 ReadUInt16()
		{
			byte[] data;
			try {
				data = _reader.ReadBytes(2);
				if (data.Length != 2) {
					throw new EndOfStreamException();
				}
			} catch (Exception) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Error reading UInt16 in HandshakeStream");
			}

			if (BitConverter.IsLittleEndian) {
				Array.Reverse(data);
			}
			return BitConverter.ToUInt16(data, 0);
		}

		public UInt32 ReadUInt24()
		{
			byte[] idata;
			try {
				idata = _reader.ReadBytes(3);
				if (idata.Length != 3) {
					throw new EndOfStreamException();
				}
			} catch (Exception) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Error reading UInt24 in HandshakeStream");
			}

			byte[] odata = new byte[4];
			Array.Copy(idata, 0, odata, odata.Length-idata.Length, idata.Length);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(odata);
			}
			return BitConverter.ToUInt32(odata, 0);
		}

		public UInt32 ReadUInt32()
		{
			byte[] data;
			try {
				data = _reader.ReadBytes(4);
				if (data.Length != 4) {
					throw new EndOfStreamException();
				}
			} catch (Exception) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Error reading UInt24 in HandshakeStream");
			}

			if (BitConverter.IsLittleEndian) {
				Array.Reverse(data);
			}
			return BitConverter.ToUInt32(data, 0);
		}

		public byte[] ReadBytes(int count)
		{
			byte[] data;
			try {
				data = _reader.ReadBytes(count);
				if (data.Length != count) {
					throw new EndOfStreamException();
				}
			} catch (Exception) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Error reading " + count + " bytes of data in HandshakeStream");
			}
			return data;
		}

		public void WriteUInt8(Byte value)
		{
			_writer.Write(value);
		}

		public void WriteUInt16(UInt16 value)
		{
			byte[] data = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(data);
			}
			_writer.Write(data);
		}

		public void WriteUInt24(UInt32 value)
		{
			byte[] data = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(data);
			}
			_writer.Write(data, 1, 3);
		}

		public void WriteUInt32(UInt32 value)
		{
			byte[] data = BitConverter.GetBytes(value);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(data);
			}
			_writer.Write(data);
		}

		public void WriteBytes(byte[] data)
		{
			_writer.Write(data);
		}
	}
}
