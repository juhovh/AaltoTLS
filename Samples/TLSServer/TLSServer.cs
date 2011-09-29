//
// TLSServer - sample TLS server using SecureSession
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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AaltoTLS.HandshakeLayer;
using AaltoTLS.PluginInterface;

namespace AaltoTLS
{
	public class TLSServer
	{
		private TcpClient _client;
		private SecurityParameters _securityParameters;

		public TLSServer(TcpClient client, SecurityParameters securityParameters) {
			_client = client;
			_securityParameters = securityParameters;
		}

		public static void Main(string[] args)
		{
			SecurityParameters securityParameters = new SecurityParameters();
			securityParameters.MaximumVersion = ProtocolVersion.SSL3_0;
			if (args.Length < 2) {
				Console.WriteLine("Usage: TLSServer.exe cert.pem key.xml");
				return;
			} else if (args.Length >= 2) {
				X509CertificateCollection certs = new X509CertificateCollection();
				for (int i=0; i<args.Length-1; i++) {
					certs.Add(new X509Certificate(args[i]));
				}
				
				// Get plugin manager for importing the private key
				string path = System.Reflection.Assembly.GetAssembly(typeof(HandshakeSession)).Location;
				string directory = Path.GetDirectoryName(path);
				CipherSuitePluginManager pluginManager = new CipherSuitePluginManager(directory);
				
				// Import the private key into asymmetric algorithm
				byte[] privateKeyData = File.ReadAllBytes(args[args.Length-1]);
				CertificatePrivateKey privateKey = pluginManager.GetPrivateKey(privateKeyData);
				
				securityParameters.AddCertificate(certs, privateKey);
				securityParameters.CipherSuiteIDs.AddRange(pluginManager.GetSupportedCipherSuiteIDs(securityParameters.MaximumVersion, certs[0], false));
			}

			try {
				TcpListener tcpListener = new TcpListener(IPAddress.Any, 4433);
				tcpListener.Start();

				while (true) {
					TcpClient tcpClient = tcpListener.AcceptTcpClient();
					Console.WriteLine("Accepted client");

					TLSServer server = new TLSServer(tcpClient, securityParameters);
					Thread thread = new Thread(new ThreadStart(server.Thread));
					thread.Start();
				}
			} catch (SocketException) {
				Console.WriteLine("Unable to listen to socket");
				return;
			}
		}

		private void Thread()
		{
			try {
				NetworkStream ns = _client.GetStream();
				SecureSession session = new SecureSession(ns, _securityParameters);
				session.PerformServerHandshake(null);
				if (session.Receive() != null) {
					session.Send(Encoding.UTF8.GetBytes(RESPONSE));
				}
				session.Close();
				Console.WriteLine("Finish reader thread");
			} catch (Exception) {}
		}
		
		private static readonly string RESPONSE =
			"HTTP/1.1 200 OK\r\n" +
			"Content-Length: 27\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\nTLS connection successful!\n";
	}
}
