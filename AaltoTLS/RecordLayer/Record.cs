//
// AaltoTLS.RecordLayer.Record
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
using AaltoTLS.PluginInterface;

namespace AaltoTLS.RecordLayer
{
	public class Record
	{
		private byte _type;
		private ProtocolVersion _version;
		private UInt16 _epoch;
		private UInt64 _seqNum;
		private byte[] _fragment;
	
		public byte Type
		{
			get { return _type; }
		}
		
		public ProtocolVersion Version
		{
			get { return _version; }
		}
		
		public UInt16 Epoch
		{
			get { return _epoch; }
			set { _epoch = value; }
		}
		
		public UInt64 SequenceNumber
		{
			get { return _seqNum; }
			set { _seqNum = value; }
		}

		public byte[] Fragment
		{
			get { return _fragment; }
			set {
				if (value == null) {
					_fragment = new byte[0];
				} else {
					_fragment = value;
				}
			}
		}
		
		public Record(byte type, ProtocolVersion version)
			: this(type, version, new byte[0])
		{
		}
		
		public Record(byte type, ProtocolVersion version, byte[] fragment)
		{
			_type = type;
			_version = version;
			_fragment = fragment;
		}
		
		public Record(byte[] header)
		{
			_type = header[0];
			_version = new ProtocolVersion(header[1], header[2]);
			if (_version.IsUsingDatagrams) {
				_epoch = (UInt16) ((header[3] << 8) | header[4]);
				for (int i=0; i<6; i++) {
					_seqNum <<= 8;
					_seqNum |= header[5+i];
				}
				_fragment = new byte[(header[11] << 8) | header[12]];
			} else {
				_fragment = new byte[(header[3] << 8) | header[4]];
			}
		}
		
		public byte[] GetBytes()
		{
			byte[] fragment = this.Fragment;
			
			byte[] ret;
			if (_version.IsUsingDatagrams) {
				ret = new byte[13+fragment.Length];
				
				ret[0] = Type;
				ret[1] = Version.Major;
				ret[2] = Version.Minor;
				ret[3] = (byte) (_epoch >> 8);
				ret[4] = (byte) (_epoch);
				for (int i=0; i<6; i++) {
					ret[5+i] = (byte) (_seqNum >> (5-i));
				}
				ret[11] = (byte) (fragment.Length >> 8);
				ret[12] = (byte) (fragment.Length);
				Array.Copy(fragment, 0, ret, 12, fragment.Length);
			} else {
				ret = new byte[5+fragment.Length];

				ret[0] = Type;
				ret[1] = Version.Major;
				ret[2] = Version.Minor;
				ret[3] = (byte) (fragment.Length >> 8);
				ret[4] = (byte) (fragment.Length);
				Array.Copy(fragment, 0, ret, 5, fragment.Length);
			}
			return ret;
		}
	}
}
