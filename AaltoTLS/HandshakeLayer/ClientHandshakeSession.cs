//
// AaltoTLS.HandshakeLayer.ClientHandshakeSession
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
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;
using AaltoTLS.HandshakeLayer.Protocol;

namespace AaltoTLS.HandshakeLayer
{
	public class ClientHandshakeSession : HandshakeSession
	{
		private ServerCertificateValidationCallback _certificateValidationCallback;
		private ClientCertificateSelectionCallback _certificateSelectionCallback;
		
		private bool _clientCertificateRequested;
		
		private bool DefaultCertificateValidationCallback(X509CertificateCollection certificates)
		{
			return false;
		}
		
		private int DefaultCertificateSelectionCallback(X509CertificateCollection[] clientCertificates, X509CertificateCollection serverCertificate)
		{
			return -1;
		}
		
		public ClientHandshakeSession(SecurityParameters securityParameters)
			: base(securityParameters)
		{
			if (securityParameters.ServerCertificateValidationCallback != null) {
				_certificateValidationCallback = securityParameters.ServerCertificateValidationCallback;
			} else {
				_certificateValidationCallback = new ServerCertificateValidationCallback(DefaultCertificateValidationCallback);
			}
			if (securityParameters.ClientCertificateSelectionCallback != null) {
				_certificateSelectionCallback = securityParameters.ClientCertificateSelectionCallback;
			} else {
				_certificateSelectionCallback = new ClientCertificateSelectionCallback(DefaultCertificateSelectionCallback);
			}
			
			
			HandshakeClientHello clientHello = new HandshakeClientHello(_maxVersion);
			clientHello.CipherSuites.AddRange(_supportedCipherSuites);
			clientHello.CompressionMethods.AddRange(_supportedCompressions);
			clientHello.Extensions.Add(new HelloSignatureAlgorithmsExtension(_pluginManager.GetSupportedSignatureAndHashAlgorithms()));
			OutputMessage(clientHello);

			_connectionState.ClientRandom = clientHello.Random.GetBytes();
		}

		protected override void ProcessHelloRequest()
		{
			// TODO: if negotiating ignore, otherwise MAY initiate, no hashes
		}

		protected override void ProcessServerHello(HandshakeServerHello serverHello)
		{
			if (_state != HandshakeState.Initial) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Client hello received at the wrong time");
			}
			
			if (serverHello.ServerVersion < _minVersion || serverHello.ServerVersion > _maxVersion) {
				throw new AlertException(AlertDescription.ProtocolVersion,
				                         "Server version is not acceptable");
			}

			_version = serverHello.ServerVersion;
			_connectionState.ServerRandom = serverHello.Random.GetBytes();
			_cipherSuite = _pluginManager.GetCipherSuite(_version, serverHello.CipherSuite);
			if (_cipherSuite == null) {
				throw new AlertException(AlertDescription.HandshakeFailure,
				                         "Got incorrect cipher suite from server");
			}
			
			// TODO: If we resumed our session, set state to WaitForChangeCipherSpec and return
			
			// Wait for server certificate (server key exchange in case of DH_anon)
			_state = HandshakeState.ReceivedServerHello;
		}

		protected override void ProcessCertificate(HandshakeCertificate certificate)
		{
			if (_state != HandshakeState.ReceivedServerHello) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Certificate received at the wrong time");
			}
			
			if (certificate.CertificateList.Count == 0) {
				throw new AlertException(AlertDescription.BadCertificate,
				                         "Certificate chain has no entries");
			}
			_serverCertificates.AddRange(certificate.CertificateList);
			
			string keyexAlg = _cipherSuite.KeyExchangeAlgorithm.CertificateKeyAlgorithm;
			string signAlg = _cipherSuite.SignatureAlgorithm.CertificateKeyAlgorithm;
			
			// Check that certificate is valid
			X509Certificate cert = _serverCertificates[0];
			if (keyexAlg != null && !keyexAlg.Equals(cert.GetKeyAlgorithm())) {
				throw new AlertException(AlertDescription.BadCertificate,
				                         "Certificate type " + cert.GetKeyAlgorithm() + " doesn't match key exchange type " + keyexAlg);
			}
			if (signAlg != null && !signAlg.Equals(cert.GetKeyAlgorithm())) {
				throw new AlertException(AlertDescription.BadCertificate,
				                         "Certificate type " + cert.GetKeyAlgorithm() + " doesn't match signature type " + signAlg);
			}
			
			// Validate certificate chain
			if (!_certificateValidationCallback(certificate.CertificateList)) {
				throw new AlertException(AlertDescription.AccessDenied,
				                         "Server certificate was not accepted");
			}
			
			// Wait for server key exchange, certificate request or server hello done
			_state = HandshakeState.ReceivedCertificate;
		}

		protected override void ProcessServerKeyExchange(HandshakeMessage keyExchange)
		{
			if (_state != HandshakeState.ReceivedServerHello &&
			    _state != HandshakeState.ReceivedCertificate) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Server key exchange received at the wrong time");
			}
			if (!_cipherSuite.IsAnonymous && _serverCertificates.Count == 0) {
				throw new AlertException(AlertDescription.HandshakeFailure,
				                         "No certificate received even though cipher suite is not anonymous");
			}
			
			// Process server keys, also returns us the signature data
			byte[] signature = _cipherSuite.KeyExchangeAlgorithm.ProcessServerKeys(_version, keyExchange.Data);
			
			// Extract the signed data from the complete payload
			byte[] serverKeys = new byte[keyExchange.Data.Length - signature.Length];
			Buffer.BlockCopy(keyExchange.Data, 0, serverKeys, 0, serverKeys.Length);

			// Verify correctness of the signature
			if (!_cipherSuite.IsAnonymous) {
				CertificatePublicKey publicKey = new CertificatePublicKey(_serverCertificates[0]);
				
				// Generate the original data signed from server keys
				byte[] signedData = new byte[_connectionState.ClientRandom.Length + _connectionState.ServerRandom.Length + serverKeys.Length];
				Buffer.BlockCopy(_connectionState.ClientRandom, 0, signedData, 0, _connectionState.ClientRandom.Length);
				Buffer.BlockCopy(_connectionState.ServerRandom, 0, signedData, _connectionState.ClientRandom.Length, _connectionState.ServerRandom.Length);
				Buffer.BlockCopy(serverKeys, 0, signedData, _connectionState.ClientRandom.Length + _connectionState.ServerRandom.Length, serverKeys.Length);
				
				bool signatureOk = VerifySignature(publicKey, signedData, signature);
				if (!signatureOk) {
					throw new AlertException(AlertDescription.DecodeError,
					                         "Signature from server incorrect");
				}
			}

			// Wait for certificate request or server hello done
			_state = HandshakeState.ReceivedServerKeyExchange;
		}
		
		protected override void ProcessCertificateRequest(HandshakeCertificateRequest request)
		{
			if (_state != HandshakeState.ReceivedCertificate &&
			    _state != HandshakeState.ReceivedServerKeyExchange) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Certificate request received at the wrong time");
			}
			if (_cipherSuite.IsAnonymous) {
				throw new AlertException(AlertDescription.HandshakeFailure,
				                         "Certificate request on anonymous cipher suite received");
			}
			
			// Mark client certificate as requested
			_clientCertificateRequested = true;
			
			Console.WriteLine("Client certificate requested");
			Console.WriteLine("Types:");
			for (int i=0; i<request.CertificateTypes.Count; i++) {
				Console.WriteLine("  " + i + ": " + request.CertificateTypes[i]);
			}
			Console.WriteLine("Algorithms:");
			for (int i=0; i<request.SignatureAndHashAlgorithms.Count; i++) {
				Console.WriteLine("  " + i + ": " + request.SignatureAndHashAlgorithms[i]);
			}
			
			// Wait for server hello done
			_state = HandshakeState.ReceivedCertificateRequest;
		}

		protected override void ProcessServerHelloDone(HandshakeMessage serverHelloDone)
		{
			if (_state != HandshakeState.ReceivedCertificate &&
			    _state != HandshakeState.ReceivedServerKeyExchange &&
			    _state != HandshakeState.ReceivedCertificateRequest) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Server hello done received at the wrong time");
			}
			
			bool clientCertificateSent = false;
			if (_clientCertificateRequested) {
				// Ask for correct certificate from the callback
				int certificateIndex = _certificateSelectionCallback(_availableCertificates.ToArray(), _serverCertificates);
				if (certificateIndex >= 0 && certificateIndex < _availableCertificates.Count) {
					_clientCertificates.AddRange(_availableCertificates[certificateIndex]);
					_selectedPrivateKey = _availablePrivateKeys[certificateIndex];
				}
				
				// If certificate was selected, send it to server
				if (_clientCertificates.Count > 0) {
					HandshakeCertificate certificate = new HandshakeCertificate(_version);
					certificate.CertificateList.AddRange(_clientCertificates);
					OutputMessage(certificate);
					
					clientCertificateSent = true;
				} else {
					// TODO: In case of SSLv3 we should send warning alert instead?
					HandshakeCertificate certificate = new HandshakeCertificate(_version);
					OutputMessage(certificate);
				}
			}

			// Send client key exchange message
			byte[] clientKeys = null;
			if (_serverCertificates.Count > 0) {
				CertificatePublicKey publicKey = new CertificatePublicKey(_serverCertificates[0]);
				clientKeys = _cipherSuite.KeyExchangeAlgorithm.GetClientKeys(_version, _maxVersion, publicKey);
			}
			HandshakeMessage keyex = new HandshakeMessage(HandshakeMessageType.ClientKeyExchange, _version, clientKeys);
			OutputMessage(keyex);
			
			if (clientCertificateSent) {
				// Get all handshake messages
				byte[] handshakeMessages = _handshakeStream.ToArray();
				
				// FIXME: Generate the signature of handshakeMessages with client cert signature
				//        this breaks if client certificate signature is different type than negotiated
				byte[] signature = GenerateSignature(_selectedPrivateKey, handshakeMessages);
				
				// Create CertificateVerify message and send it to server
				HandshakeMessage verify = new HandshakeMessage(HandshakeMessageType.CertificateVerify, _version, signature);
				OutputMessage(verify);
			}
			
			// Generate the master secret from key exchange
			_connectionState.MasterSecret = GenerateMasterSecret(_version, _cipherSuite, _connectionState);
			
			// Wait for changecipherspec+finished
			_state = HandshakeState.SendChangeCipherSpec;
		}
		
		protected override void ProcessLocalChangeCipherSpec()
		{
			if (_state != HandshakeState.SendChangeCipherSpec) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Change cipher spec not after server hello done");
			}
			byte[] handshakeMessages = _handshakeStream.ToArray();

			PseudoRandomFunction prf = _cipherSuite.PseudoRandomFunction;
			HashAlgorithm verifyHash = prf.CreateVerifyHashAlgorithm(_connectionState.MasterSecret);
			verifyHash.TransformBlock(handshakeMessages, 0, handshakeMessages.Length, handshakeMessages, 0);
			
			byte[] verifyData;
			if (_version == ProtocolVersion.SSL3_0) {
				byte[] senderBytes = Encoding.ASCII.GetBytes("CLNT");
				verifyHash.TransformFinalBlock(senderBytes, 0, senderBytes.Length);
				verifyData = verifyHash.Hash;
			} else {
				verifyHash.TransformFinalBlock(new byte[0], 0, 0);
				byte[] hash = verifyHash.Hash;

				int length = _cipherSuite.PseudoRandomFunction.VerifyDataLength;
				verifyData = _cipherSuite.PseudoRandomFunction.GetBytes(_connectionState.MasterSecret, "client finished", hash, length);
			}
			_connectionState.ClientVerifyData = verifyData;
			
			// Output the handshake message including verify data
			HandshakeMessage finished = new HandshakeMessage(HandshakeMessageType.Finished, _version, verifyData);
			OutputMessage(finished);
			
			_state = HandshakeState.WaitForChangeCipherSpec;
		}

		protected override void ProcessRemoteChangeCipherSpec()
		{
			if (_state != HandshakeState.WaitForChangeCipherSpec) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Change cipher spec not after sending finished");
			}
			_state = HandshakeState.ReceivedChangeCipherSpec;
		}

		protected override void ProcessFinished(HandshakeMessage finished)
		{
			if (_state != HandshakeState.ReceivedChangeCipherSpec) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Finished message received at the wrong time");
			}

			byte[] allMessages = _handshakeStream.ToArray();
			byte[] handshakeMessages = new byte[allMessages.Length - finished.Encode().Length];
			Buffer.BlockCopy(allMessages, 0, handshakeMessages, 0, handshakeMessages.Length);

			PseudoRandomFunction prf = _cipherSuite.PseudoRandomFunction;
			HashAlgorithm verifyHash = prf.CreateVerifyHashAlgorithm(_connectionState.MasterSecret);
			verifyHash.TransformBlock(handshakeMessages, 0, handshakeMessages.Length, handshakeMessages, 0);
			
			byte[] ourVerifyData;
			if (_version == ProtocolVersion.SSL3_0) {
				byte[] senderBytes = Encoding.ASCII.GetBytes("SRVR");
				verifyHash.TransformFinalBlock(senderBytes, 0, senderBytes.Length);
				ourVerifyData = verifyHash.Hash;
			} else {
				verifyHash.TransformFinalBlock(new byte[0], 0, 0);
				byte[] hash = verifyHash.Hash;

				int length = _cipherSuite.PseudoRandomFunction.VerifyDataLength;
				ourVerifyData = _cipherSuite.PseudoRandomFunction.GetBytes(_connectionState.MasterSecret, "server finished", hash, length);
			}
			
			// Verify that the received data matches ours
			bool verifyOk = false;
			if (ourVerifyData.Length == finished.Data.Length) {
				verifyOk = true;
				for (int i=0; i<ourVerifyData.Length; i++) {
					if (ourVerifyData[i] != finished.Data[i]) {
						verifyOk = false;
					}
				}
			}
			
			if (!verifyOk) {
				throw new AlertException(AlertDescription.DecryptError,
				                         "Finished packet contents incorrect");
			}
			_connectionState.ServerVerifyData = ourVerifyData;
			
			// Cleanup the handshake stream used for verify hashes
			_handshakeStream = new MemoryStream();
			
			// Everything done and handshake finished
			_state = HandshakeState.Finished;
		}
	}
}
