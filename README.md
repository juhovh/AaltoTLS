Introduction
------------

AaltoTLS is an implementation of the SSL/TLS network protocol written completely
using C# and standard cryptographic libraries of .NET where relevant. It is
designed to run fully on open source Mono implementation as well, working around
possible bugs and incompatibilities if present. Focus of the project has been
mainly on clean layered structure of the code and easy extensibility, not so
much on performance or memory use. This is because the project has originally
been part of a research project. So benchmarking might be required before using
it in production environments.


License
-------

All code is released under the following MIT/X11 license unless otherwise
stated:

```
Copyright (C) 2010-2011  Aalto University

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```


Compiling the source code
-------------------------

There are two methods supported for compiling the source code. The preferred one
is using NAnt, in which running command "nant" in the AaltoTLS folder should
compile all source files to AaltoTLS-debug folder. If you wish to compile a
release build without the debugging information, it can be done running the
command "nant release" and it will compile the files to AaltoTLS-release
folder.

In development the MonoDevelop 2.6 IDE is used as well, and all the necessary
project files should be included. In this case opening the AaltoTLS.sln in
MonoDevelop should open the solution and "Build All" should build all the source
files into their respective folders.


Supported TLS features
----------------------

Protocol support:           SSLv3.0, TLSv1.0, TLSv1.1, TLSv1.2
Key exchange algorithms:    RSA, DHE, ECDHE
Signature algorithms:       RSA, DSS, ECDSA
Encryption algorithms:      RC4, DES-CBC, 3DES-CBC, AES-CBC, AES-GCM, SEED, Camellia, ARIA-CBC, ARIA-GCM
MAC algorithms:             SSLv3, MD5, SHA-1, SHA-256, SHA-384, SHA-512
Pseudorandom functions:     SSLv3, TLSv1, TLSv1.2 (SHA-256, SHA-384, SHA-512)


Future work to do
-----------------

Important work to do:
- Logging system that doesn't output to stdout
- Cipher suite selection based on security features

Less important features:
- TLS 1.2 signature_algorithms extension support
- Session resume using the SessionID of ClientHello
- Renegotiation support as described in RFC 5746

Clean up to be done:
- TLSSession and HandshakeSession both need cleaning up
- Better API for TLSSession required, like TcpClient


Implementation details
----------------------

Resolved library issues:

RSACryptoServiceProvider.SignData doesn't accept MD5SHA1CryptoServiceProvider,
because it doesn't have an OID. If RSA signatures is to be supported in SSL
3.0, TLS 1.0 and TLS 1.1, it needs to be done manually. That's why
SignatureAlgorithmRSA depends on BigInteger and is not included in the base
cipher suite plugin. The TLS 1.2 version of it doesn't depend on BigInteger at
all.

Support for ECC cipher suites was done using the ECDiffieHellmanCng and ECDsaCng
classes that are provided by .NET 3.5 when run on Windows 7, Windows Vista SP1
or later or Windows XP SP3. They are not available on older versions of Windows
or on other operating systems using Mono, therefore they are excluded from the
NAnt build file to cause as little trouble as possible. It's also worth to note
that using ECDiffieHellmanCng with TLS 1.2 is impossible, because the API
requires including premaster secret as part of the HMAC input. It's a stupid
API, but there's not much that can be done. SSLv3, TLSv1.0 and TLSv1.1 are
currently supported.


Things to note:

ARCFour cipher is separated into its own plugin, because it includes references
to RC4, which in turn is trademarked by RSA Security. Including this cipher is
highly recommended, since many servers only support RC4 ciphers for their fast
speed and simple implementation.

Diffie-Hellman and RSA signing depend on BigInteger implementation, which is not
available in .NET before the version 4.0. Since by the time of writing this
.NET 4.0 is not very widely used, a modified version of Microsoft BigInteger
implementation that should be almost identical with .NET 4.0 BigInteger is
included in the plugin. The BigInteger implementation is released under
Microsoft Public License, which is a free software license but not compatible
with GNU GPL.

Camellia cipher is separated into its own plugin, because it includes MIT
licensed CamelliaEngine class copyrighted by The Legion Of The Bouncy Castle.
The license is quite liberal, but because of copyright issues it is better to
keep it as a separate plugin. Camellia is quite widely used and even preferred
by some servers, so including this plugin is recommended.

ARIA cipher is separated into its own plugin, because it includes a MIT licensed
ARIAEngine with different copyright. ARIA is not a very common cipher to be used
with TLS and it is probably only used inside South Korea, so this should not be
an issue. It is included because the plugin is a very good sample plugin of how
to easily add CBC and GCM mode cipher suites with a crypto library where only
ECB is available.


Outstanding issues:

When running on Mono and not on real .NET, validating the certificate chain is
currently not possible, because Mono doesn't implement the X509 certificate
chain validation. Therefore it will always fail when run on Mono but will work
when run on .NET.

TLS 1.2 is fully supported, but the SignatureAlgorithms extension is not
supported, which means that all signatures are signed using SHA-1 hash. This
should not be an issue, since SHA-1 is still considered secure, but in the
future it might be good to upgrade support for stronger hash algorithms.

Deflate compression is supported by .NET in DeflateStream class, but this class
is not useful for our purposes. TLS requires that the deflate compression can
compress single packets as a continuous stream, but flush each packet separately
in the middle and send it through the wire. In Microsoft implementation of
DeflateStream the Flush() method is not implemented at all and therefore we
would have to compress each packet separately. This results in considerable
overhead and makes deflate perform badly in most use cases.


Server key generation
---------------------

Example key generation using openssl:

RSA keys (from 384 bits to 16384 bits in increments of 8 bits, 2048 used):
> openssl genrsa -out rsakey.pem 2048
> openssl req -new -x509 -days 365 -subj '/C=FI/ST=Uusimaa/L=Espoo/O=Aalto University/CN=localhost' -key rsakey.pem -out rsaca.pem
> openssl x509 -in rsaca.pem -outform DER -out rsaca.der
> ./PEM2XML.exe rsakey.pem rsakey.xml

DSA keys (from 512 bits to 1024 bits in increments of 64 bits, 1024 used):
> openssl dsaparam -noout -out dsakey.pem -genkey 1024
> openssl req -new -x509 -days 365 -subj '/C=FI/ST=Uusimaa/L=Espoo/O=Aalto University/CN=localhost' -key dsakey.pem -out dsaca.pem
> openssl x509 -in dsaca.pem -outform DER -out dsaca.der
> ./PEM2XML.exe dsakey.pem dsakey.xml

ECDSAkeys (either secp256r1, secp384r1 or secp521r1, secp256r1 used):
> openssl ecparam -noout -out ecdsakey.pem -genkey -name secp256r1
> openssl req -new -x509 -days 365 -subj '/C=FI/ST=Uusimaa/L=Espoo/O=Aalto University/CN=localhost' -key ecdsakey.pem -out ecdsaca.pem
> openssl x509 -in ecdsaca.pem -outform DER -out ecdsaca.der
> ./PEM2CNG.exe ecdsakey.pem ecdsakey.cng

Starting the server
> ./TLSServer.exe rsaca.der rsakey.xml
> ./TLSServer.exe dsaca.der dsakey.xml
> ./TLSServer.exe ecdsaca.der ecdsakey.cng

If you want to decrypt the resulting traffic using Wireshark, then go to
Preferences->Protocols->SSL and modify the "RSA keys list" to include:

"*,4433,http,[keypath]/rsa.key"

This should make Wireshark decrypt all connections that use RSA key exchange
method. The DH or DHE sessions cannot be decrypted, because Wireshark is unable
to obtain the pre-master secret from DH parameters, which is the point of
perfect forward secrecy provided by DH.

After all this, connecting to "https://localhost:4433" with any browser should
work, except that it is giving a warning about the certificate not being signed
by a known root CA, this is normal. If you do have a certificate signed by a
known root CA and with intermediate certificates, you can start TLSServer with:

> ./TLSServer.exe server.cer intermediate.cer key.xml



