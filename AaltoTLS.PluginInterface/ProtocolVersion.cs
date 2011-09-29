//
// AaltoTLS.PluginInterface.ProtocolVersion
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

namespace AaltoTLS.PluginInterface
{
	public struct ProtocolVersion
	{
		public static readonly ProtocolVersion NULL   = new ProtocolVersion();
		public static readonly ProtocolVersion SSL3_0 = new ProtocolVersion(3, 0);
		public static readonly ProtocolVersion TLS1_0 = new ProtocolVersion(3, 1);
		public static readonly ProtocolVersion TLS1_1 = new ProtocolVersion(3, 2);
		public static readonly ProtocolVersion TLS1_2 = new ProtocolVersion(3, 3);
		
		public static readonly ProtocolVersion DTLS1_0 = new ProtocolVersion(254, 255);
		public static readonly ProtocolVersion DTLS1_2 = new ProtocolVersion(254, 253);
	
		public readonly Byte Major;
		public readonly Byte Minor;

		public ProtocolVersion(byte major, byte minor)
		{
			this.Major = major;
			this.Minor = minor;
		}
		
		public bool IsUsingDatagrams
		{
			get { return (Major > 128); }
		}
		
		
		// These are similar with GnuTLS gnutls_algorithm.c file
		public bool HasSelectablePRF
		{
			get { return (this == ProtocolVersion.TLS1_2 || this == ProtocolVersion.DTLS1_2); }
		}
		
		public bool HasSelectableSighash
		{
			get { return (this == ProtocolVersion.TLS1_2 || this == ProtocolVersion.DTLS1_2); }
		}
		
		public bool HasExtensions
		{
			get {
				return ((this >= ProtocolVersion.TLS1_0 && this <= ProtocolVersion.TLS1_2) ||
				        (this >= ProtocolVersion.DTLS1_0 && this <= ProtocolVersion.DTLS1_2));
			}
		}
		
		public bool HasExplicitIV
		{
			get {
				return ((this >= ProtocolVersion.TLS1_1 && this <= ProtocolVersion.TLS1_2) ||
				        (this >= ProtocolVersion.DTLS1_0 && this <= ProtocolVersion.DTLS1_2));
			}
		}
		
		public bool HasVariablePadding
		{
			get {
				return ((this >= ProtocolVersion.TLS1_0 && this <= ProtocolVersion.TLS1_2) ||
				        (this >= ProtocolVersion.DTLS1_0 && this <= ProtocolVersion.DTLS1_2));
			}
		}
		
		public bool HasVerifiablePadding
		{
			get {
				return ((this >= ProtocolVersion.TLS1_0 && this <= ProtocolVersion.TLS1_2) ||
				        (this >= ProtocolVersion.DTLS1_0 && this <= ProtocolVersion.DTLS1_2));
			}
		}
		
		public bool HasAeadSupport
		{
			get { return (this == ProtocolVersion.TLS1_2 || this == ProtocolVersion.DTLS1_2); }
		}
		
		public ProtocolVersion PreviousProtocolVersion
		{
			get {
				if (this == ProtocolVersion.TLS1_2)
					return ProtocolVersion.TLS1_1;
				if (this == ProtocolVersion.TLS1_1)
					return ProtocolVersion.TLS1_0;
				if (this == ProtocolVersion.TLS1_0)
					return ProtocolVersion.SSL3_0;
				if (this == ProtocolVersion.DTLS1_2)
					return ProtocolVersion.DTLS1_0;
				throw new ArgumentOutOfRangeException("This is the first supported protocol version");
			}
		}



		// Define the overloaded methods and operators
		public override string ToString()
		{
			string ret;

			if (this == ProtocolVersion.NULL) {
				ret = "NULL";
			} else if (this < ProtocolVersion.TLS1_0) {
				ret = "SSLv" + this.Major + "." + this.Minor;
			} else if (this.Major == 3) {
				ret = "TLSv1." + (this.Minor - 1);
			} else if (!this.IsUsingDatagrams) {
				ret = "TLSv" + (this.Major - 2) + "." + this.Minor;
			} else {
				ret = "DTLSv" + (255 - this.Major) + "." + (255 - this.Minor);
			}

			return ret;
		}

		public override bool Equals(Object obj)
		{
			if (obj == null || GetType() != obj.GetType()) return false;
			
			ProtocolVersion version = (ProtocolVersion) obj;
			return ((this.Major == version.Major) && (this.Minor == version.Minor));
		}
		
		public override int GetHashCode()
		{
			return ((this.Major << 8) | this.Minor);
		}
		
		public static bool operator ==(ProtocolVersion a, ProtocolVersion b)
		{
			return ((a.Major == b.Major) && (a.Minor == b.Minor));
		}
		
		public static bool operator !=(ProtocolVersion a, ProtocolVersion b)
		{
			return ((a.Major != b.Major) || (a.Minor != b.Minor));
		}

		public static bool operator <(ProtocolVersion a, ProtocolVersion b)
		{
			if (a.IsUsingDatagrams != b.IsUsingDatagrams) {
				// Can't compare TLS with DTLS, always return false
				return false;
			}
			if (!a.IsUsingDatagrams) {
				if (a.Major < b.Major) return true;
				if (a.Major > b.Major) return false;
				if (a.Minor < b.Minor) return true;
			} else {
				if (a.Major > b.Major) return true;
				if (a.Major < b.Major) return false;
				if (a.Minor > b.Minor) return true;
			}
			return false;
		}
		
		public static bool operator >(ProtocolVersion a, ProtocolVersion b)
		{
			if (a.IsUsingDatagrams != b.IsUsingDatagrams) {
				// Can't compare TLS with DTLS, always return false
				return false;
			}
			if (!a.IsUsingDatagrams) {
				if (a.Major > b.Major) return true;
				if (a.Major < b.Major) return false;
				if (a.Minor > b.Minor) return true;
			} else {
				if (a.Major < b.Major) return true;
				if (a.Major > b.Major) return false;
				if (a.Minor < b.Minor) return true;
			}
			return false;
		}
		
		public static bool operator <=(ProtocolVersion a, ProtocolVersion b)
		{
			return ((a < b) || (a == b));
		}
		
		public static bool operator >=(ProtocolVersion a, ProtocolVersion b)
		{
			return ((a > b) || (a == b));
		}
	}
}
