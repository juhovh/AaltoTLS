using System;

namespace AaltoTLS.Authentication
{
	/* Constants taken from http://msdn.microsoft.com/en-us/library/aa375549%28v=VS.85%29.aspx */
	public enum ExchangeAlgorithmType
	{
		None            = 0x0000,
		RsaKeyX         = 0xA400,
		DiffieHellman   = 0xAA02,
		ECDiffieHellman = 0xAA05
	}
}

