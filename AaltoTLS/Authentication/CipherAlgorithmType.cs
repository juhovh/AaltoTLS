using System;

namespace AaltoTLS.Authentication
{
	/* Constants taken from http://msdn.microsoft.com/en-us/library/aa375549%28v=VS.85%29.aspx */
	public enum CipherAlgorithmType {
		None       = 0x0000,
		Null       = 0x6000,
		Des        = 0x6601,
		TripleDes  = 0x6603,
		Aes128     = 0x660e,
		Aes192     = 0x660f,
		Aes256     = 0x6610,
		Aes        = 0x6611,
		Rc4        = 0x6801
	}
}

