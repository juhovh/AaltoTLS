//
// AaltoTLS.HandshakeLayer.ServerHandshakeSession
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
	public class ServerHandshakeSession : HandshakeSession
	{
		private ServerCertificateSelectionCallback _certificateSelectionCallback;
		
		// Max version sent by the client
		private ProtocolVersion _clientVersion;
		
		// This is set in case we are able to send a certificate request
		private readonly HandshakeCertificateRequest _certificateRequest = null;
		private bool _certificateRequestSent;
		private bool _clientCertificateReceived;
		
		private static int DefaultCertificateSelectionCallback(CipherSuite cipherSuite, X509CertificateCollection[] availableCertificates)
		{
			// No certificate for anonymous suites
			if (cipherSuite.IsAnonymous)
				return -1;
			
			for (int i=0; i<availableCertificates.Length; i++) {
				X509CertificateCollection certs = availableCertificates[i];
				if (certs.Count == 0)
					continue;
				
				string keyexAlg = cipherSuite.KeyExchangeAlgorithm.CertificateKeyAlgorithm;
				string sigAlg = cipherSuite.SignatureAlgorithm.CertificateKeyAlgorithm;
				
				if (keyexAlg != null && !keyexAlg.Equals(certs[0].GetKeyAlgorithm()))
					continue;
				if (sigAlg != null && !sigAlg.Equals(certs[0].GetKeyAlgorithm()))
					continue;
				
				return i;
			}
			return -1;
		}
		
		private static CipherSuite SelectCipherSuite(CipherSuitePluginManager pluginManager,
			ProtocolVersion clientVersion, ProtocolVersion minVersion, ProtocolVersion maxVersion,
			List<UInt16> clientSuites, List<UInt16> serverSuites,
			ServerCertificateSelectionCallback certificateSelectionCallback,
			List<X509CertificateCollection> availableCertificates)
		{
			if (clientVersion < minVersion) {
				throw new AlertException(AlertDescription.ProtocolVersion,
				                         "Offered client version " + clientVersion +
				                         " lower than minimum supported version " + minVersion);
			}
			
			// Initialize our return value as null
			CipherSuite selectedCipherSuite = null;
			
			// Run as long as we either select a cipher suite or run out of versions
			ProtocolVersion selectedVersion = clientVersion < maxVersion ? clientVersion : maxVersion;
			while (selectedCipherSuite == null) {
				foreach (UInt16 id in clientSuites) {
					if (!serverSuites.Contains(id))
						continue;
					
					// Try initializing the cipher suite based on ID
					selectedCipherSuite = pluginManager.GetCipherSuite(selectedVersion, id);
					if (selectedCipherSuite == null)
						continue;
					
					// Try selecting a suitable certificate for this cipher suite
					int certificateIndex = certificateSelectionCallback(selectedCipherSuite, availableCertificates.ToArray());
					if (certificateIndex >= 0 && certificateIndex < availableCertificates.Count) {
						// We finally found the valid suite, break out from the loop
						break;
					}
					// No certificate was found for the suite, ignore
					selectedCipherSuite = null;
				}
				
				if (selectedCipherSuite != null) break;
				if (selectedVersion == minVersion) break;
				selectedVersion = selectedVersion.PreviousProtocolVersion;
			}
			
			if (selectedCipherSuite == null) {
				throw new AlertException(AlertDescription.HandshakeFailure,
				                         "None of the cipher suites offered by client is accepted");
			}
			return selectedCipherSuite;
		}
		
		public ServerHandshakeSession(SecurityParameters securityParameters)
			: base(securityParameters)
		{
			if (securityParameters.ServerCertificateSelectionCallback != null) {
				_certificateSelectionCallback = securityParameters.ServerCertificateSelectionCallback;
			} else {
				_certificateSelectionCallback = new ServerCertificateSelectionCallback(DefaultCertificateSelectionCallback);
			}
			
			_availableCertificates = new List<X509CertificateCollection>();
			_availableCertificates.AddRange(securityParameters.AvailableCertificates);
			
			_availablePrivateKeys = new List<CertificatePrivateKey>();
			_availablePrivateKeys.AddRange(securityParameters.AvailablePrivateKeys);

			if (securityParameters.ClientCertificateTypes.Count > 0) {
				_certificateRequest = new HandshakeCertificateRequest(_version);
				_certificateRequest.CertificateTypes.AddRange(securityParameters.ClientCertificateTypes);
				_certificateRequest.SignatureAndHashAlgorithms.AddRange(_pluginManager.GetSupportedSignatureAndHashAlgorithms());
				_certificateRequest.CertificateAuthorities.AddRange(securityParameters.ClientCertificateAuthorities);
			}
		}

		protected override void ProcessClientHello(HandshakeClientHello clientHello)
		{
			if (_state == HandshakeState.Finished) {
				throw new AlertException(AlertDescription.NoRenegotiation,
				                         "Renegotiation not supported");
			} else if (_state != HandshakeState.Initial) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Client hello received at the wrong time");
			}
			
			// Find the compressions that match our supported compressions
			List<Byte> matchedCompressions = new List<Byte>();
			foreach (Byte id in _supportedCompressions) {
				if (clientHello.CompressionMethods.Contains(id)) {
					matchedCompressions.Add(id);
				}
			}
			if (matchedCompressions.Count == 0) {
				throw new AlertException(AlertDescription.HandshakeFailure,
				                         "None of the compression methods offered by client is accepted");
			}
			
			_clientVersion = clientHello.ClientVersion;
			_cipherSuite = SelectCipherSuite(_pluginManager, _clientVersion, _minVersion, _maxVersion, clientHello.CipherSuites, new List<UInt16>(_supportedCipherSuites), _certificateSelectionCallback, _availableCertificates);
			_version = _cipherSuite.ProtocolVersion;
			
			// Select the certificate and private key we are going to send
			int certificateIndex = _certificateSelectionCallback(_cipherSuite, _availableCertificates.ToArray());
			if (certificateIndex >= 0 && certificateIndex < _availableCertificates.Count) {
				_serverCertificates.AddRange(_availableCertificates[certificateIndex]);
				_selectedPrivateKey = _availablePrivateKeys[certificateIndex];
			}

			// TODO: Create the server hello message correctly
			HandshakeServerHello serverHello = new HandshakeServerHello(_version);
			serverHello.CipherSuite = _cipherSuite.CipherSuiteID;
			serverHello.CompressionMethod = matchedCompressions[0];
			OutputMessage(serverHello);

			// Initialize the handshake randoms and cipher suite
			_connectionState.ClientRandom = clientHello.Random.GetBytes();
			_connectionState.ServerRandom = serverHello.Random.GetBytes();
			
			// TODO: If we resumed our session, set state to SendChangeCipherSpec and return
			
			// Send certificate if required and valid
			if (!_cipherSuite.IsAnonymous) {
				if (_serverCertificates.Count == 0) {
					throw new AlertException(AlertDescription.HandshakeFailure,
					                         "Certificate required but not selected");
				}
				
				string keyexAlg = _cipherSuite.KeyExchangeAlgorithm.CertificateKeyAlgorithm;
				string signAlg = _cipherSuite.SignatureAlgorithm.CertificateKeyAlgorithm;
				
				X509Certificate cert = _serverCertificates[0];
				if (keyexAlg != null && !keyexAlg.Equals(cert.GetKeyAlgorithm())) {
					throw new AlertException(AlertDescription.HandshakeFailure,
					                         "Selected certificate type " + cert.GetKeyAlgorithm() + " doesn't match key exchange type " + keyexAlg);
				}
				if (signAlg != null && !signAlg.Equals(cert.GetKeyAlgorithm())) {
					throw new AlertException(AlertDescription.HandshakeFailure,
					                         "Selected certificate type " + cert.GetKeyAlgorithm() + " doesn't match signature type " + signAlg);
				}

				HandshakeCertificate certificate = new HandshakeCertificate(_version);
				certificate.CertificateList.AddRange(_serverCertificates);
				OutputMessage(certificate);
			}
			
			byte[] serverKeys = _cipherSuite.KeyExchangeAlgorithm.GetServerKeys(_maxVersion);
			if (serverKeys != null) {
				// Generate the signature for server keys
				byte[] dataToSign = new byte[_connectionState.ClientRandom.Length + _connectionState.ServerRandom.Length + serverKeys.Length];
				Buffer.BlockCopy(_connectionState.ClientRandom, 0, dataToSign, 0, _connectionState.ClientRandom.Length);
				Buffer.BlockCopy(_connectionState.ServerRandom, 0, dataToSign, _connectionState.ClientRandom.Length, _connectionState.ServerRandom.Length);
				Buffer.BlockCopy(serverKeys, 0, dataToSign, _connectionState.ClientRandom.Length + _connectionState.ServerRandom.Length, serverKeys.Length);
				byte[] signature = GenerateSignature(_selectedPrivateKey, dataToSign);
				
				// Combine the server keys with the signature
				byte[] signedKeys = new byte[serverKeys.Length + signature.Length];
				Buffer.BlockCopy(serverKeys, 0, signedKeys, 0, serverKeys.Length);
				Buffer.BlockCopy(signature, 0, signedKeys, serverKeys.Length, signature.Length);
				
				HandshakeMessage keyex = new HandshakeMessage(HandshakeMessageType.ServerKeyExchange, _version, signedKeys);
				OutputMessage(keyex);
			}
			
			// Send certificate request if needed
			if (!_cipherSuite.IsAnonymous && _certificateRequest != null) {
				OutputMessage(_certificateRequest);
				_certificateRequestSent = true;
			}
			
			HandshakeMessage serverHelloDone = new HandshakeMessage(HandshakeMessageType.ServerHelloDone, _version);
			OutputMessage(serverHelloDone);

			// Wait for client certificate or client key exchange
			_state = HandshakeState.ReceivedClientHello;
		}

		protected override void ProcessCertificate(HandshakeCertificate certificate)
		{
			if (_state != HandshakeState.ReceivedClientHello) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Client certificate received at the wrong time");
			}
			if (!_certificateRequestSent) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Client certificate received even though request was not sent");
			}
			
			if (certificate.CertificateList.Count > 0) {
				_clientCertificateReceived = true;
			}
			_clientCertificates.AddRange(certificate.CertificateList);
			
			// Wait for client key exchange
			_state = HandshakeState.ReceivedCertificate;
		}

		protected override void ProcessClientKeyExchange(HandshakeMessage keyExchange)
		{
			if (_state != HandshakeState.ReceivedClientHello &&
			    _state != HandshakeState.ReceivedCertificate) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Client key exchange received at the wrong time");
			}
			if (_state == HandshakeState.ReceivedClientHello && _certificateRequestSent) {
				// SSLv3 can use NoCertificate warning alert instead
				if (_version != ProtocolVersion.SSL3_0) {
					throw new AlertException(AlertDescription.UnexpectedMessage,
					                         "Certificate request was sent, but client didn't send a certificate");
				}
			}
			
			// Process client keys, they don't contain any signature but might be encrypted
			_cipherSuite.KeyExchangeAlgorithm.ProcessClientKeys(_version, _clientVersion, _selectedPrivateKey, keyExchange.Data);
			
			// Wait for certificate verify or changecipherspec+finished
			_state = HandshakeState.ReceivedClientKeyExchange;
		}

		protected override void ProcessCertificateVerify(HandshakeMessage verify)
		{
			if (_state != HandshakeState.ReceivedClientKeyExchange) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Certificate verify received at the wrong time");
			}
			if (!_clientCertificateReceived) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Certificate verify received even though client certificate not received");
			}
			
			// Get all handshake messages up to, but not including, this one
			byte[] allMessages = _handshakeStream.ToArray();
			byte[] handshakeMessages = new byte[allMessages.Length - verify.Encode().Length];
			Buffer.BlockCopy(allMessages, 0, handshakeMessages, 0, handshakeMessages.Length);
			
			// Verify the signature of handshake messages
			CertificatePublicKey publicKey = new CertificatePublicKey(_clientCertificates[0]);
			bool signatureOk = VerifySignature(publicKey, handshakeMessages, verify.Data);
			if (!signatureOk) {
				throw new AlertException(AlertDescription.DecodeError,
				                         "Signature from client incorrect");
			}

			// Wait for changecipherspec+finished
			_state = HandshakeState.ReceivedClientKeyExchange;
		}

		protected override void ProcessRemoteChangeCipherSpec()
		{
			if (_state != HandshakeState.ReceivedClientKeyExchange &&
			    _state != HandshakeState.ReceivedCertificateVerify) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Change cipher spec from client received at the wrong time");
			}
			if (_state == HandshakeState.ReceivedClientKeyExchange && _clientCertificateReceived) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Certificate request was sent, but client didn't send a certificate verify");
			}
			
			_connectionState.MasterSecret = GenerateMasterSecret(_version, _cipherSuite, _connectionState);
			_state = HandshakeState.ReceivedChangeCipherSpec;
		}

		protected override void ProcessFinished(HandshakeMessage finished)
		{
			if (_state != HandshakeState.ReceivedChangeCipherSpec) {
				throw new AlertException(AlertDescription.UnexpectedMessage,
				                         "Finished received at the wrong time");
			}
			
			byte[] allMessages = _handshakeStream.ToArray();
			byte[] handshakeMessages = new byte[allMessages.Length - finished.Encode().Length];
			Buffer.BlockCopy(allMessages, 0, handshakeMessages, 0, handshakeMessages.Length);

			PseudoRandomFunction prf = _cipherSuite.PseudoRandomFunction;
			HashAlgorithm verifyHash = prf.CreateVerifyHashAlgorithm(_connectionState.MasterSecret);
			verifyHash.TransformBlock(handshakeMessages, 0, handshakeMessages.Length, handshakeMessages, 0);
			
			byte[] ourVerifyData;
			if (_version == ProtocolVersion.SSL3_0) {
				byte[] senderBytes = Encoding.ASCII.GetBytes("CLNT");
				verifyHash.TransformFinalBlock(senderBytes, 0, senderBytes.Length);
				ourVerifyData = verifyHash.Hash;
			} else {
				verifyHash.TransformFinalBlock(new byte[0], 0, 0);
				byte[] hash = verifyHash.Hash;

				int length = _cipherSuite.PseudoRandomFunction.VerifyDataLength;
				ourVerifyData = _cipherSuite.PseudoRandomFunction.GetBytes(_connectionState.MasterSecret, "client finished", hash, length);
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
			_connectionState.ClientVerifyData = ourVerifyData;

			// Send our own change cipher spec
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
				byte[] senderBytes = Encoding.ASCII.GetBytes("SRVR");
				verifyHash.TransformFinalBlock(senderBytes, 0, senderBytes.Length);
				verifyData = verifyHash.Hash;
			} else {
				verifyHash.TransformFinalBlock(new byte[0], 0, 0);
				byte[] hash = verifyHash.Hash;

				int length = _cipherSuite.PseudoRandomFunction.VerifyDataLength;
				verifyData = _cipherSuite.PseudoRandomFunction.GetBytes(_connectionState.MasterSecret, "server finished", hash, length);
			}
			_connectionState.ServerVerifyData = verifyData;
			
			HandshakeMessage finished = new HandshakeMessage(HandshakeMessageType.Finished, _version, verifyData);
			OutputMessage(finished);
			
			// Cleanup the handshake stream used for verify hashes
			_handshakeStream = new MemoryStream();
			
			// Everything done and handshake finished
			_state = HandshakeState.Finished;
		}
	}
}

