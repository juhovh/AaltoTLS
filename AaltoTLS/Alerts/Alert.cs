//
// AaltoTLS.Alerts.Alert
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

namespace AaltoTLS.Alerts
{
	public class Alert
	{
		public AlertLevel        Level;
		public AlertDescription  Description;
		
		public Alert(AlertDescription description, ProtocolVersion version)
			: this(AlertLevel.Fatal, description, version) {}
		
		public Alert(AlertLevel level, AlertDescription description, ProtocolVersion version)
		{
			Level = level;
			Description = description;
			ValidateForProtocolVersion(version);
		}
		
		private void ValidateForProtocolVersion(ProtocolVersion version)
		{
			switch (Description) {
			// Warning alerts that are SSLv3 only
			case AlertDescription.NoCertificate:
				Level = AlertLevel.Warning;
				if (version != ProtocolVersion.SSL3_0)
					Level = AlertLevel.None;
				break;
				
			// Warning alerts supported in all versions
			case AlertDescription.CloseNotify:
				Level = AlertLevel.Warning;
				break;

			// Fatal alerts supported in all versions
			case AlertDescription.UnexpectedMessage:
			case AlertDescription.BadRecordMAC:
			case AlertDescription.DecompressionFailure:
			case AlertDescription.HandshakeFailure:
			case AlertDescription.IllegalParameter:
				Level = AlertLevel.Fatal;
				break;
				
			// Other alerts supported in all versions
			case AlertDescription.BadCertificate:
			case AlertDescription.UnsupportedCertificate:
			case AlertDescription.CertificateRevoked:
			case AlertDescription.CertificateExpired:
			case AlertDescription.CertificateUnknown:
				break;

			// Fatal alerts that are TLS only
			case AlertDescription.UnknownCA:
			case AlertDescription.AccessDenied:
				Level = AlertLevel.Fatal;
				if (version == ProtocolVersion.SSL3_0)
					Description = AlertDescription.CertificateUnknown;
				break;
			case AlertDescription.RecordOverflow:
			case AlertDescription.DecodeError:
			case AlertDescription.DecryptError:
			case AlertDescription.InternalError:
				Level = AlertLevel.Fatal;
				if (version == ProtocolVersion.SSL3_0)
					Description = AlertDescription.IllegalParameter;
				break;
			case AlertDescription.ProtocolVersion:
			case AlertDescription.InsufficientSecurity:
				Level = AlertLevel.Fatal;
				if (version == ProtocolVersion.SSL3_0)
					Description = AlertDescription.HandshakeFailure;
				break;
			
			// Warning alerts that are TLS only
			case AlertDescription.UserCanceled:
			case AlertDescription.NoRenegotiation:
				Level = AlertLevel.Warning;
				if (version == ProtocolVersion.SSL3_0)
					Level = AlertLevel.None;
				break;
			
			// Fatal alerts that are TLSv1.2 only
			case AlertDescription.UnsupportedExtension:
				Level = AlertLevel.Fatal;
				if (version != ProtocolVersion.TLS1_2)
					Description = AlertDescription.IllegalParameter;
				break;
			}
		}
		
		public Alert(byte[] data)
		{
			Level = AlertLevel.Fatal;
			Description = AlertDescription.IllegalParameter;
			
			if (data.Length == 2) {
				Level = (AlertLevel) data[0];
				Description = (AlertDescription) data[1];
			}
		}
		
		public byte[] GetBytes()
		{
			byte[] ret = new byte[2];
			ret[0] = (byte) Level;
			ret[1] = (byte) Description;
			return ret;
		}
	}
}
