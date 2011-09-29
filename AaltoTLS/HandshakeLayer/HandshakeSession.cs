//
// AaltoTLS.HandshakeLayer.HandshakeSession
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
	public abstract class HandshakeSession
	{
		protected List<HandshakeMessage> _outputMessages = new List<HandshakeMessage>();
		protected MemoryStream _handshakeStream = new MemoryStream();

		protected CipherSuitePluginManager _pluginManager;
		protected HandshakeState _state;

		// These are directly from SecurityParameters
		protected readonly ProtocolVersion _minVersion;
		protected readonly ProtocolVersion _maxVersion;
		protected readonly UInt16[] _supportedCipherSuites;
		protected readonly Byte[] _supportedCompressions;
		
		// These are options for our client/server certificate
		protected List<X509CertificateCollection> _availableCertificates;
		protected List<CertificatePrivateKey>     _availablePrivateKeys;
		
		// These will be filled with the certificates during handshake
		protected readonly X509CertificateCollection _clientCertificates;
		protected readonly X509CertificateCollection _serverCertificates;
		
		// This is the private key we will use for signing
		protected CertificatePrivateKey _selectedPrivateKey;
		
		// Negotiated protocol version and cipher suite
		protected ProtocolVersion _version;
		protected CipherSuite _cipherSuite;
		
		// Connection state, including client and server randoms
		protected ConnectionState _connectionState;
		
		public HandshakeState State
		{
			get { return _state; }
		}
		
		public ProtocolVersion NegotiatedVersion
		{
			get { return _version; }
		}
		
		public CipherSuite CipherSuite
		{
			get { return _cipherSuite; }
		}
		
		public ConnectionState ConnectionState
		{
			get { return _connectionState; }
		}

		protected HandshakeSession(SecurityParameters securityParameters)
		{
			string path = System.Reflection.Assembly.GetAssembly(typeof(HandshakeSession)).Location;
			string directory = Path.GetDirectoryName(path);

			_pluginManager = new CipherSuitePluginManager(directory);
			_state = HandshakeState.Initial;

			_minVersion = securityParameters.MinimumVersion;
			_maxVersion = securityParameters.MaximumVersion;
			_supportedCipherSuites = securityParameters.CipherSuiteIDs.ToArray();
			_supportedCompressions = securityParameters.CompressionIDs.ToArray();
			
			_availableCertificates = new List<X509CertificateCollection>(securityParameters.AvailableCertificates);
			_availablePrivateKeys = new List<CertificatePrivateKey>(securityParameters.AvailablePrivateKeys);
			
			_clientCertificates = new X509CertificateCollection();
			_serverCertificates = new X509CertificateCollection();
			
			// Initialize the default ClientHello version, to
			// be as compatible as possible based on maxVersion
			if (_maxVersion == ProtocolVersion.SSL3_0) {
				_version = ProtocolVersion.SSL3_0;
			} else if (_maxVersion.IsUsingDatagrams) {
				_version = ProtocolVersion.DTLS1_0;
			} else {
				_version = ProtocolVersion.TLS1_0;
			}
			_cipherSuite = new CipherSuite(_version);
		}
		
		protected static byte[] GenerateMasterSecret(ProtocolVersion version, CipherSuite cipherSuite, ConnectionState connectionState)
		{
			byte[] seed = new byte[64];
			Array.Copy(connectionState.ClientRandom, 0, seed, 0, 32);
			Array.Copy(connectionState.ServerRandom, 0, seed, 32, 32);

			byte[] masterSecret = cipherSuite.KeyExchangeAlgorithm.GetMasterSecret(cipherSuite.PseudoRandomFunction, seed);
			if (masterSecret == null) {
				throw new Exception("Could not generate master secret");
			}
			return masterSecret;
		}
		
		protected HashAlgorithm GetSignatureHashAlgorithm(SignatureAlgorithm signatureAlgorithm, byte hashAlgorithmType)
		{
			if (!signatureAlgorithm.SupportsHashAlgorithmType(hashAlgorithmType)) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Illegal hash algorithm type");
			}
			
			HashAlgorithm hashAlgorithm;
			switch (hashAlgorithmType) {
			case 1:
				hashAlgorithm = new MD5CryptoServiceProvider();
				break;
			case 2:
				hashAlgorithm = new SHA1CryptoServiceProvider();
				break;
			case 4:
				hashAlgorithm = new SHA256Managed();
				break;
			case 5:
				hashAlgorithm = new SHA384Managed();
				break;
			case 6:
				hashAlgorithm = new SHA512Managed();
				break;
			default:
				throw new AlertException(AlertDescription.InternalError,
				                         "Unsupported hash algorithm type: " + hashAlgorithmType);
			}
			
			return hashAlgorithm;
		}
		
		protected byte[] GenerateSignature(CertificatePrivateKey privateKey, byte[] data)
		{
			// This array contains our results
			byte[] signedParams = new byte[0];
			byte[] temp;
			
			// Get the corresponding signer for private key
			SignatureAlgorithm sigAlg = _pluginManager.GetSignatureAlgorithmByOid(privateKey.Oid);
			if (sigAlg == null) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Signer for given private key not found");
			}
			
			// Select hash algorithm, null means SSLv3/TLSv1 hash
			HashAlgorithm hashAlgorithm = null;
			if (_version.HasSelectableSighash) {
				// FIXME: Not checked to be same as negotiated, but SHA-1 should be safe
				byte hashAlgorithmType = 2; // SHA-1
				byte signAlgorithmType = sigAlg.SignatureAlgorithmType;
				hashAlgorithm = GetSignatureHashAlgorithm(sigAlg, hashAlgorithmType);
				
				// Update signed parameters
				temp = new byte[signedParams.Length + 2];
				Buffer.BlockCopy(signedParams, 0, temp, 0, signedParams.Length);
				temp[signedParams.Length]   = hashAlgorithmType;
				temp[signedParams.Length+1] = signAlgorithmType;
				signedParams = temp;
			}
			
			// Sign the actual data
			byte[] signature = sigAlg.SignData(_version, data, hashAlgorithm, privateKey);
			
			// Add signature to the end of the signedParams
			temp = new byte[signedParams.Length + 2 + signature.Length];
			Buffer.BlockCopy(signedParams, 0, temp, 0, signedParams.Length);
			temp[signedParams.Length]   = (byte) (signature.Length >> 8);
			temp[signedParams.Length+1] = (byte) (signature.Length);
			Buffer.BlockCopy(signature, 0, temp, signedParams.Length+2, signature.Length);
			signedParams = temp;
			
			return signedParams;
		}
		
		protected bool VerifySignature(CertificatePublicKey publicKey, byte[] data, byte[] signedParams)
		{
			// Initialize the signature position and validity
			int position = 0;
			bool signatureOk = false;

			// Get the corresponding signer for public key
			SignatureAlgorithm sigAlg = _pluginManager.GetSignatureAlgorithmByOid(publicKey.Oid);
			if (sigAlg == null) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Signer for given public key not found");
			}
			
			// Select hash algorithm, null means SSLv3/TLSv1 hash
			HashAlgorithm hashAlgorithm = null;
			if (_version.HasSelectableSighash) {
				byte hashAlgorithmType = signedParams[position++];
				byte signAlgorithmType = signedParams[position++];
				if (sigAlg.SignatureAlgorithmType != signAlgorithmType) {
					throw new AlertException(AlertDescription.DecryptError,
					                         "Certificate signed with invalid signature algorithm");
				}
				if (!sigAlg.SupportsHashAlgorithmType(hashAlgorithmType)) {
					throw new AlertException(AlertDescription.DecryptError,
					                         "Certificate signed with invalid hash algorithm");
				}
				hashAlgorithm = GetSignatureHashAlgorithm(sigAlg, hashAlgorithmType);
			}

			// Check that signature length is valid (same as stored)
			int len = (signedParams[position] << 8) | signedParams[position+1];
			if (len != signedParams.Length-position-2) {
				throw new AlertException(AlertDescription.DecodeError,
				                         "Signature length not valid");
			}
			position += 2;
			
			// Extract the signature from the end of the signed parameters
			byte[] signature = new byte[len];
			Buffer.BlockCopy(signedParams, position, signature, 0, len);

			// Verify correctness of the signature
			signatureOk = sigAlg.VerifyData(_version, data, hashAlgorithm, publicKey, signature);
			if (!signatureOk) {
				throw new AlertException(AlertDescription.DecodeError,
				                         "Signature from server incorrect");
			}
			
			return signatureOk;
		}

		protected void OutputMessage(HandshakeMessage message)
		{
			byte[] data = message.Encode();
			_handshakeStream.Write(data, 0, data.Length);
			
			_outputMessages.Add(message);
		}
		
		public void ProcessMessage(HandshakeMessage message)
		{
			byte[] msgData = message.Encode();
			_handshakeStream.Write(msgData, 0, msgData.Length);
			
			switch (message.Type) {
			case HandshakeMessageType.HelloRequest:
				ProcessHelloRequest();
				break;
			case HandshakeMessageType.ClientHello:
				ProcessClientHello((HandshakeClientHello) message);
				break;
			case HandshakeMessageType.ServerHello:
				ProcessServerHello((HandshakeServerHello) message);
				break;
			case HandshakeMessageType.NewSessionTicket:
				ProcessNewSessionTicket(message);
				break;
			case HandshakeMessageType.Certificate:
				ProcessCertificate((HandshakeCertificate) message);
				break;
			case HandshakeMessageType.ServerKeyExchange:
				ProcessServerKeyExchange(message);
				break;
			case HandshakeMessageType.CertificateRequest:
				ProcessCertificateRequest((HandshakeCertificateRequest)message);
				break;
			case HandshakeMessageType.ServerHelloDone:
				ProcessServerHelloDone(message);
				break;
			case HandshakeMessageType.CertificateVerify:
				ProcessCertificateVerify(message);
				break;
			case HandshakeMessageType.ClientKeyExchange:
				ProcessClientKeyExchange(message);
				break;
			case HandshakeMessageType.Finished:
				ProcessFinished(message);
				break;
			}
		}
		
		public void LocalChangeCipherSpec()
		{
			if (_outputMessages.Count > 0) {
				_outputMessages.Clear();
			}
			ProcessLocalChangeCipherSpec();
		}
		
		public void RemoteChangeCipherSpec()
		{
			ProcessRemoteChangeCipherSpec();
		}
		
		public HandshakeMessage[] GetOutputMessages()
		{
			HandshakeMessage[] ret;
			
			// Return and clear output messages
			ret = _outputMessages.ToArray();
			_outputMessages.Clear();
			
			return ret;
		}

		private void InvalidMessageReceived()
		{
			throw new AlertException(AlertDescription.UnexpectedMessage,
			                         "Invalid handshake message received");
		}

		protected virtual void ProcessLocalChangeCipherSpec()                                 { InvalidMessageReceived(); }
		protected virtual void ProcessRemoteChangeCipherSpec()                                { InvalidMessageReceived(); }

		// Messages received by the client
		protected virtual void ProcessHelloRequest()                                          { InvalidMessageReceived(); }
		protected virtual void ProcessServerHello(HandshakeServerHello serverHello)           { InvalidMessageReceived(); }
		protected virtual void ProcessServerKeyExchange(HandshakeMessage keyExchange)         { InvalidMessageReceived(); }
		protected virtual void ProcessCertificateRequest(HandshakeCertificateRequest request) { InvalidMessageReceived(); }
		protected virtual void ProcessServerHelloDone(HandshakeMessage serverHelloDone)       { InvalidMessageReceived(); }
		protected virtual void ProcessNewSessionTicket(HandshakeMessage ticket)               { InvalidMessageReceived(); }

		// Messages received by the server
		protected virtual void ProcessClientHello(HandshakeClientHello clientHello)           { InvalidMessageReceived(); }
		protected virtual void ProcessClientKeyExchange(HandshakeMessage keyExchange)         { InvalidMessageReceived(); }
		protected virtual void ProcessCertificateVerify(HandshakeMessage verify)              { InvalidMessageReceived(); }

		// Messages received by both
		protected virtual void ProcessCertificate(HandshakeCertificate certificate)           { InvalidMessageReceived(); }
		protected virtual void ProcessFinished(HandshakeMessage finished)                     { InvalidMessageReceived(); }
	}
}

