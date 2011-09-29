using System;

namespace AaltoTLS.Authentication
{
	[Flags]
	public enum SslProtocols
	{
		None     = 0x00,
		Ssl2     = 0x0C,
		Ssl3     = 0x30,
		Tls      = 0xC0,
		Default  = Ssl3 | Tls
	}
}

