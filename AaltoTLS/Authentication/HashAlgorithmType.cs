using System;

namespace AaltoTLS.Authentication
{
	/* Constants taken from http://msdn.microsoft.com/en-us/library/aa375549%28v=VS.85%29.aspx */
	public enum HashAlgorithmType
	{
		None    = 0x0000,
		Md5     = 0x8003,
		Sha1    = 0x8004,
		Sha256  = 0x800C,
		Sha384  = 0x800D,
		Sha512  = 0x800E
	}
}

