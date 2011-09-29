//
// TLSRecordHandlerTest - sample TLS client WITHOUT using SecureSession
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
using AaltoTLS.RecordLayer;
using AaltoTLS.PluginInterface;
using AaltoTLS.HandshakeLayer.Protocol;

namespace TLSRecordHandlerTest
{
	public class TLSRecordHandlerTest
	{
		private string _server;
		private int _port;
		
		private CipherSuitePluginManager _pluginManager;
		private MemoryStream _handshakeStream = new MemoryStream();
		private CipherSuite _cipherSuite;
		private CertificatePublicKey _rsaPublicKey;
		private RecordHandler _recordHandler;

		private byte[] _clientRandom;
		private byte[] _serverRandom;
		private byte[] _masterSecret;

		private ProtocolVersion VERSION = ProtocolVersion.SSL3_0;
		private const UInt16 CIPHER_SUITE = 0x0035;

		public TLSRecordHandlerTest(string server, int port)
		{
			string path = System.Reflection.Assembly.GetAssembly(typeof(TLSRecordHandlerTest)).Location;
			string directory = Path.GetDirectoryName(path);

			_server = server;
			_port = port;
			
			_pluginManager = new CipherSuitePluginManager(directory);
			_cipherSuite = _pluginManager.GetCipherSuite(VERSION, CIPHER_SUITE);
			if (_cipherSuite != null) {
				Console.WriteLine("Got cipher suite");
			} else {
				throw new Exception("Error finding cipher suite!");
			}
			_recordHandler = new RecordHandler(VERSION, true);
		}

		private void SendRecord(Stream stream, Record record)
		{
			if (record.Type == 22) {
				Console.WriteLine("adding bytes to hash " + record.Fragment.Length);
				_handshakeStream.Write(record.Fragment, 0, record.Fragment.Length);
			}

			byte[] data = record.GetBytes();
			stream.Write(data, 0, data.Length);
		}

		public void SendClientHello(Stream stream)
		{
			HandshakeClientHello hello = new HandshakeClientHello(VERSION);
			_clientRandom = hello.Random.GetBytes();
			hello.CipherSuites.Add(CIPHER_SUITE);
			hello.CompressionMethods.Add(0);

			Record record = new Record(22, VERSION);
			record.Fragment = hello.Encode();
			
			_recordHandler.ProcessOutputRecord(record);
			SendRecord(stream, record);
		}

		public void PrintBytes(string name, byte[] data)
		{
			Console.Write(name + "[" + data.Length + "]:");
			for (int i=0; i<data.Length; i++) {
				if (i%16 == 0) Console.WriteLine("");
				Console.Write(data[i].ToString("x").PadLeft(2, '0') + " ");
			}
			Console.WriteLine("");
		}

		public void SendClientKey(Stream stream)
		{
			byte[] clientKeys = _cipherSuite.KeyExchangeAlgorithm.GetClientKeys(VERSION, VERSION, _rsaPublicKey);
			if (VERSION != ProtocolVersion.SSL3_0) {
				byte[] tmpArray = new byte[clientKeys.Length+2];
				tmpArray[0] = (byte) (clientKeys.Length >> 8);
				tmpArray[1] = (byte) (clientKeys.Length);
				Buffer.BlockCopy(clientKeys, 0, tmpArray, 2, clientKeys.Length);
				clientKeys = tmpArray;
			}
			HandshakeMessage keyex = new HandshakeMessage(HandshakeMessageType.ClientKeyExchange, VERSION, clientKeys);
			
			Record record = new Record(22, VERSION);
			record.Fragment = keyex.Encode();
			_recordHandler.ProcessOutputRecord(record);
			SendRecord(stream, record);
		}
		
		public void SendFinished(Stream stream)
		{
			Record record;

			/* change cipher spec */
			record = new Record(20, VERSION);
			record.Fragment = new byte[] { 0x01 };
			_recordHandler.ProcessOutputRecord(record);
			SendRecord(stream, record);

			/* change our own cipher spec */
			_recordHandler.ChangeLocalState();


			ProtocolVersion version = VERSION;
			byte[] handshakeMessages = _handshakeStream.ToArray();
			Console.WriteLine("handshake messages length " + handshakeMessages.Length);
			
			PseudoRandomFunction prf = _cipherSuite.PseudoRandomFunction;
			HashAlgorithm verifyHash = prf.CreateVerifyHashAlgorithm(_masterSecret);
			verifyHash.TransformBlock(handshakeMessages, 0, handshakeMessages.Length, handshakeMessages, 0);
			
			byte[] verifyData;
			if (version == ProtocolVersion.SSL3_0) {
				byte[] senderBytes = Encoding.ASCII.GetBytes("CLNT");
				verifyHash.TransformFinalBlock(senderBytes, 0, senderBytes.Length);
				verifyData = verifyHash.Hash;
			} else {
				verifyHash.TransformFinalBlock(new byte[0], 0, 0);
				byte[] hash = verifyHash.Hash;

				int length = _cipherSuite.PseudoRandomFunction.VerifyDataLength;
				verifyData = _cipherSuite.PseudoRandomFunction.GetBytes(_masterSecret, "client finished", hash, length);
			}
			HandshakeMessage finished = new HandshakeMessage(HandshakeMessageType.Finished, VERSION, verifyData);
			PrintBytes("verify data", finished.Data);
			
			record = new Record(22, VERSION);
			record.Fragment = finished.Encode();
			_recordHandler.ProcessOutputRecord(record);
			SendRecord(stream, record);
			
			Console.WriteLine("encrypted finished sent");
		}

		public void SendHttpGet(Stream stream)
		{
			Record record = new Record(23, VERSION);
			record.Fragment = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n");
			
			_recordHandler.ProcessOutputRecord(record);
			SendRecord(stream, record);
			Console.WriteLine("encrypted packet sent");
		}

		public bool ReadPacket(Stream stream)
		{
			byte[] header = new byte[5];
			int readBytes = 0;
			while (readBytes < header.Length) {
				readBytes += stream.Read(header, readBytes, header.Length-readBytes);
			}
			
			Record record = new Record(header);
			readBytes = 0;
			while (readBytes < record.Fragment.Length) {
				readBytes += stream.Read(record.Fragment, readBytes, record.Fragment.Length-readBytes);
			}
			
			_recordHandler.ProcessInputRecord(record);

			if (record.Type == 22) {
				HandshakeMessage hs = HandshakeMessage.GetInstance(VERSION, record.Fragment);
				if (hs == null) {
					Console.WriteLine("Skipped handling packet");
					return true;
				}

				Console.WriteLine("adding bytes to hash " + record.Fragment.Length);
				_handshakeStream.Write(record.Fragment, 0, record.Fragment.Length);

				if (hs.Type == HandshakeMessageType.ServerHello) {
					HandshakeServerHello sh = (HandshakeServerHello) hs;
					_serverRandom = sh.Random.GetBytes();
					if (sh.ServerVersion != VERSION) {
						throw new Exception("Version doesn't match");
					}
				} else if (hs.Type == HandshakeMessageType.Certificate) {
					Console.WriteLine("Found certificate");
					HandshakeCertificate cert = (HandshakeCertificate) hs;

					_rsaPublicKey = null;
					foreach (X509Certificate c in cert.CertificateList) {
						Console.WriteLine(c.ToString(true));

						if (_rsaPublicKey == null) {
							X509Certificate c2 = new X509Certificate(c);
							_rsaPublicKey = new CertificatePublicKey(c2);
						}
					}
				} else if (hs.Type == HandshakeMessageType.ServerHelloDone) {
					SendClientKey(stream);
					
					byte[] seed = new byte[64];
					Array.Copy(_clientRandom, 0, seed, 0, 32);
					Array.Copy(_serverRandom, 0, seed, 32, 32);
					PrintBytes("hash seed", seed);
					
					_masterSecret = _cipherSuite.KeyExchangeAlgorithm.GetMasterSecret(_cipherSuite.PseudoRandomFunction, seed);
					PrintBytes("master secret", _masterSecret);

					seed = new byte[64];
					Array.Copy(_serverRandom, 0, seed, 0, 32);
					Array.Copy(_clientRandom, 0, seed, 32, 32);
					
					ConnectionState connectionState = new ConnectionState(_clientRandom, _serverRandom, _masterSecret);
					_recordHandler.SetCipherSuite(_cipherSuite, connectionState);
					
					SendFinished(stream);
				} else if (hs.Type == HandshakeMessageType.Finished) {
					Console.WriteLine("Got Finished message!!!");
					SendHttpGet(stream);
				}
				
			} else if (record.Type == 20) {
				Console.WriteLine("Got change cipher spec from server");
				_recordHandler.ChangeRemoteState();
			} else if (record.Type == 21) {
				// This is an alert
				if (record.Fragment.Length >= 2 && record.Fragment[1] == 0) {
					// Close notify
					Console.WriteLine("Close notify received");
					return false;
				}
			} else if (record.Type == 23) {
				Console.WriteLine("Got data: " + Encoding.UTF8.GetString(record.Fragment));
				
			}
			
			return true;
		}

		public void Connect()
		{
			TcpClient tcpClient;

			try {
				tcpClient = new TcpClient(_server, _port);
			} catch (SocketException) {
				Console.WriteLine("Unable to connect to server");
				return;
			}

			NetworkStream ns = tcpClient.GetStream();
			SendClientHello(ns);
			while (ReadPacket(ns));
			Console.WriteLine("Finish reader");
		}

		public static void Main(string[] args)
		{
			TLSRecordHandlerTest client = new TLSRecordHandlerTest("www.google.com", 443);
			client.Connect();
		}
	}
}
