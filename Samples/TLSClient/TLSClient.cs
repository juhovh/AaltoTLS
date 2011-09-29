//
// TLSClient - sample TLS client using SecureSession
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

using AaltoTLS;
using AaltoTLS.PluginInterface;


namespace TLSClient
{
	public class TLSClient
	{
		private static bool CertificateValidationCallback(X509CertificateCollection serverCertificate)
		{
			return true;
		}
		
		private static int CertificateSelectionCallback(X509CertificateCollection[] clientCertificates, X509CertificateCollection serverCertificate)
		{
			if (clientCertificates.Length > 0)
				return 0;
			return -1;
		}
		
		public static void Main(string[] args)
		{
			SecurityParameters securityParameters = new SecurityParameters();
			securityParameters.CipherSuiteIDs.Add(0x000a);
			securityParameters.ServerCertificateValidationCallback = new ServerCertificateValidationCallback(CertificateValidationCallback);
			securityParameters.ClientCertificateSelectionCallback = new ClientCertificateSelectionCallback(CertificateSelectionCallback);
			
			if (args.Length >= 2) {
				X509CertificateCollection certs = new X509CertificateCollection();
				for (int i=0; i<args.Length-1; i++) {
					certs.Add(new X509Certificate(args[i]));
				}
				
				// Get plugin manager for importing the private key
				string path = System.Reflection.Assembly.GetAssembly(typeof(AaltoTLS.HandshakeLayer.HandshakeSession)).Location;
				string directory = Path.GetDirectoryName(path);
				CipherSuitePluginManager pluginManager = new CipherSuitePluginManager(directory);
				
				// Import the private key into asymmetric algorithm
				byte[] privateKeyData = File.ReadAllBytes(args[args.Length-1]);
				CertificatePrivateKey privateKey = pluginManager.GetPrivateKey(privateKeyData);
				
				securityParameters.AddCertificate(certs, privateKey);
			}
			
			string host = "www.mikestoolbox.net";
			int    port = 443;

			string request = "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
			
			try {
				TcpClient tcpClient = new TcpClient(host, port);
				NetworkStream ns = tcpClient.GetStream();
				SecureSession session = new SecureSession(ns, securityParameters);
				session.PerformClientHandshake(host);
				session.Send(Encoding.UTF8.GetBytes(request));
				byte[] received = session.Receive();
				Console.WriteLine("Received data: " + Encoding.UTF8.GetString(received));
				session.Close();
			} catch (SocketException) {
				Console.WriteLine("Unable to connect to server");
				return;
			}
		}
	}
}
