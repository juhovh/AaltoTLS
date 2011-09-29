//
// AaltoTLS.Alerts.AlertDescription
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

namespace AaltoTLS.Alerts
{
	public enum AlertDescription
	{
		// Closure alerts
		CloseNotify             = 0,

		// Error alerts
		UnexpectedMessage       = 10,
		BadRecordMAC            = 20,
//		DecryptionFailed        = 21, RESERVED: insecure, use BadRecordMac instead
		RecordOverflow          = 22, // TLS only
		DecompressionFailure    = 30,
		HandshakeFailure        = 40,
		NoCertificate           = 41, // SSLv3 only, reply to certificate request
		BadCertificate          = 42,
		UnsupportedCertificate  = 43,
		CertificateRevoked      = 44,
		CertificateExpired      = 45,
		CertificateUnknown      = 46,
		IllegalParameter        = 47,
		UnknownCA               = 48, // Alerts starting from here TLS only
		AccessDenied            = 49,
		DecodeError             = 50,
		DecryptError            = 51,
//		ExportRestriction       = 60, RESERVED: export restrictions not valid any more
		ProtocolVersion         = 70,
		InsufficientSecurity    = 71,
		InternalError           = 80,
		UserCanceled            = 90,
		NoRenegotiation         = 100,
		UnsupportedExtension    = 101, // TLSv1.2 only, shouldn't be used on earlier versions
	}
}
