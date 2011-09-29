//
// AaltoTLS.SecureSession
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
using System.Security.Cryptography.X509Certificates;

using AaltoTLS.Alerts;
using AaltoTLS.RecordLayer;
using AaltoTLS.HandshakeLayer;
using AaltoTLS.HandshakeLayer.Protocol;
using AaltoTLS.PluginInterface;

namespace AaltoTLS
{
	public class SecureSession
	{
		private SecurityParameters    _securityParameters;
		private RecordStream          _recordStream;
		private IHandshakePacketizer  _handshakePacketizer;
		
		private Object _handshakeLock = new Object();
		private bool _isHandshaking;
		private bool _isAuthenticated;
		private RecordHandler _recordHandler;
		private HandshakeSession _handshakeSession;
		
		public SecureSession(Stream stream, SecurityParameters securityParameters)
		{
			_securityParameters = securityParameters;
			_recordStream = new TLSRecordStream(stream);
			_handshakePacketizer = new TLSHandshakePacketizer();
		}
		
		#region Client and server handshake methods
		public IAsyncResult BeginClientHandshake(string targetHost,
		                                         AsyncCallback asyncCallback,
		                                         Object asyncState)
		{
			lock (_handshakeLock) {
				if (_isHandshaking) {
					throw new InvalidOperationException("Handshake already in progress");
				}
				
				if (_isAuthenticated) {
					throw new InvalidOperationException("Renegotiation not supported");
				}
				
				_recordHandler = new RecordHandler(_securityParameters.MinimumVersion, true);
				_handshakeSession = new ClientHandshakeSession(_securityParameters);
				_isHandshaking = true;
			}
			
			AsyncHandshakeResult asyncHandshakeResult = new AsyncHandshakeResult(asyncCallback, asyncState);
			ProcessSendHandshakePacket(asyncHandshakeResult);
			return asyncHandshakeResult;
		}

		public IAsyncResult BeginServerHandshake(X509Certificate serverCertificate,
		                                         AsyncCallback asyncCallback,
		                                         Object asyncState)
		{
			lock (_handshakeLock) {
				if (_isHandshaking) {
					throw new InvalidOperationException("Handshake already in progress");
				}
				
				if (_isAuthenticated) {
					throw new InvalidOperationException("Renegotiation not supported");
				}
				
				_recordHandler = new RecordHandler(_securityParameters.MinimumVersion, false);
				_handshakeSession = new ServerHandshakeSession(_securityParameters);
				_isHandshaking = true;
			}
			
			AsyncHandshakeResult asyncHandshakeResult = new AsyncHandshakeResult(asyncCallback, asyncState);
			_recordStream.BeginReceive(new AsyncCallback(ReceiveHandshakeCallback), asyncHandshakeResult);
			return asyncHandshakeResult;
		}

		private void EndHandshake(IAsyncResult asyncResult)
		{
			AsyncHandshakeResult asyncHandshakeResult = (AsyncHandshakeResult)asyncResult;
			if (!asyncHandshakeResult.IsCompleted) {
				asyncHandshakeResult.AsyncWaitHandle.WaitOne();
			}

			lock (_handshakeLock) {
				_isHandshaking = false;

				if (asyncHandshakeResult.CompletedWithException) {
					throw asyncHandshakeResult.AsyncException;
				}
				_isAuthenticated = true;
			}
		}

		public void EndClientHandshake(IAsyncResult asyncResult)
		{
			EndHandshake(asyncResult);
		}

		public void EndServerHandshake(IAsyncResult asyncResult)
		{
			EndHandshake(asyncResult);
		}
		
		public void PerformClientHandshake(string targetHost)
		{
			EndClientHandshake(BeginClientHandshake(targetHost, null, null));
		}
		
		public void PerformServerHandshake(X509Certificate serverCertificate)
		{
			EndServerHandshake(BeginServerHandshake(serverCertificate, null, null));
		}
		#endregion
		
		#region Data receiving and sending methods
		public IAsyncResult BeginReceive(AsyncCallback asyncCallback, Object asyncState)
		{
			AsyncReceiveDataResult asyncReceiveResult = new AsyncReceiveDataResult(asyncCallback, asyncState);
			lock (_handshakeLock) {
				if (!_isAuthenticated) {
					Exception e = new InvalidOperationException("Trying to receive on an unauthenticated session");
					asyncReceiveResult.SetComplete(e);
					return asyncReceiveResult;
				}
				if (_isHandshaking) {
					// Queue requests to receive data during renegotiation
					// TODO: implement this when renegotiation is implemented
					Exception e = new InvalidOperationException("Receiving data during renegotiation not implemented");
					asyncReceiveResult.SetComplete(e);
					return asyncReceiveResult;
				}
			}
			
			_recordStream.BeginReceive(new AsyncCallback(ReceiveDataCallback), asyncReceiveResult);
			return asyncReceiveResult;
		}
		
		public byte[] EndReceive(IAsyncResult asyncResult)
		{
			AsyncReceiveDataResult asyncReceiveResult = (AsyncReceiveDataResult)asyncResult;
			if (!asyncReceiveResult.IsCompleted) {
				asyncReceiveResult.AsyncWaitHandle.WaitOne();
			}

			if (asyncReceiveResult.CompletedWithException) {
				throw asyncReceiveResult.AsyncException;
			}
			return asyncReceiveResult.AsyncResult;
		}
		
		public IAsyncResult BeginSend(byte[] buffer, int offset, int count,
		                              AsyncCallback asyncCallback,
		                              Object asyncState)
		{
			AsyncSendDataResult asyncSendResult = new AsyncSendDataResult(asyncCallback, asyncState);
			lock (_handshakeLock) {
				if (!_isAuthenticated) {
					Exception e = new InvalidOperationException("Trying to send on an unauthenticated session");
					asyncSendResult.SetComplete(e);
					return asyncSendResult;
				}
				if (_isHandshaking) {
					// Queue requests to send data during renegotiation
					// TODO: implement this when renegotiation is implemented
					Exception e = new InvalidOperationException("Sending data during renegotiation not implemented");
					asyncSendResult.SetComplete(e);
					return asyncSendResult;
				}
			}
			
			// Copy the bytes to send into own buffer
			byte[] outputBuffer = new byte[count];
			Buffer.BlockCopy(buffer, offset, outputBuffer, 0, count);
			
			// Create and encrypt the data output record
			Record[] records = _handshakePacketizer.ProcessOutputData(_handshakeSession.NegotiatedVersion,
			                                                          RecordType.Data, outputBuffer,
			                                                          _recordStream.MaximumFragmentLength);
			for (int i=0; i<records.Length; i++) {
				_recordHandler.ProcessOutputRecord(records[i]);
			}
			
			// Send the data output record
			_recordStream.BeginSend(records, new AsyncCallback(SendDataCallback), asyncSendResult);
			return asyncSendResult;
		}
		
		public void EndSend(IAsyncResult asyncResult)
		{
			AsyncSendDataResult asyncSendResult = (AsyncSendDataResult)asyncResult;
			if (!asyncSendResult.IsCompleted) {
				asyncSendResult.AsyncWaitHandle.WaitOne();
			}

			if (asyncSendResult.CompletedWithException) {
				throw asyncSendResult.AsyncException;
			}
		}
		
		public byte[] Receive()
		{
			return EndReceive(BeginReceive(null, null));
		}
		
		public void Send(byte[] buffer)
		{
			Send(buffer, 0, buffer.Length);
		}
		
		public void Send(byte[] buffer, int offset, int count)
		{
			EndSend(BeginSend(buffer, offset, count, null, null));
		}
		
		public void Close()
		{
		}
		#endregion
		
		private void SendHandshakeCallback(IAsyncResult asyncResult)
		{
			AsyncHandshakeResult asyncHandshakeResult = (AsyncHandshakeResult)asyncResult.AsyncState;
			try {
				_recordStream.EndSend(asyncResult);
				lock (_handshakeLock) {
					if (_isAuthenticated && !_isHandshaking) {
						// Mark send result as complete
						asyncHandshakeResult.SetComplete();
						return;
					}
				}
				
				// Handshake not finished yet, continue performing
				ProcessSendHandshakePacket(asyncHandshakeResult);
			} catch (AlertException ae) {
				ProcessSendFatalAlert(new Alert(ae.AlertDescription, _handshakeSession.NegotiatedVersion));
				asyncHandshakeResult.SetComplete(new Exception("Connection closed because of local alert", ae));
			} catch (IOException) {
				asyncHandshakeResult.SetComplete(new EndOfStreamException("Connection closed unexpectedly"));
			} catch (Exception e) {
				ProcessSendFatalAlert(new Alert(AlertDescription.InternalError, _handshakeSession.NegotiatedVersion));
				asyncHandshakeResult.SetComplete(new Exception("Connection closed because of local error", e));
			}
		}

		private void ReceiveHandshakeCallback(IAsyncResult asyncResult)
		{
			AsyncHandshakeResult asyncHandshakeResult = (AsyncHandshakeResult)asyncResult.AsyncState;
			try {
				Record[] records = _recordStream.EndReceive(asyncResult);
				for (int i=0; i<records.Length; i++) {
					Record record = records[i];
					if (!_recordHandler.ProcessInputRecord(record)) {
						// Ignore records from invalid epoch
						continue;
					}
					
					lock (_handshakeLock) {
						if (!_isAuthenticated && record.Type == RecordType.Data) {
							// Refuse data packets before authentication
							throw new AlertException(AlertDescription.UnexpectedMessage,
							                         "Data packet received before handshake");
						}
						if (!_isHandshaking && (record.Type == RecordType.ChangeCipherSpec || record.Type == RecordType.Handshake)) {
							// Refuse ChangeCipherSpec and Handshake packets if not handshaking
							// TODO: Should handle HelloRequest if renegotiation is supported
							throw new AlertException(AlertDescription.UnexpectedMessage,
							                         "Handshake packet received outside handshake");
						}
						if (_isHandshaking && record.Type == RecordType.Data) {
							// Queue data packets during new handshake to avoid sync problems
							// TODO: Should handle the data correctly if renegotiation is supported
							throw new AlertException(AlertDescription.UnexpectedMessage,
							                         "Received a data packet during handshake");
						}
					}
					
					switch (record.Type) {
					case RecordType.ChangeCipherSpec:
						ProcessChangeCipherSpecRecord(record, asyncHandshakeResult);
						break;
					case RecordType.Alert:
						ProcessAlertRecord(record, asyncHandshakeResult);
						break;
					case RecordType.Handshake:
						ProcessHandshakeRecord(record, asyncHandshakeResult);
						break;
					case RecordType.Data:
						// TODO: Implement this properly if renegotiation is supported
						break;
					default:
						ProcessUnknownRecord(record, asyncHandshakeResult);
						break;
					}
				}
			} catch (AlertException ae) {
				ProcessSendFatalAlert(new Alert(ae.AlertDescription, _handshakeSession.NegotiatedVersion));
				asyncHandshakeResult.SetComplete(new Exception("Connection closed because of local alert", ae));
			} catch (IOException) {
				asyncHandshakeResult.SetComplete(new EndOfStreamException("Connection closed unexpectedly"));
			} catch (Exception e) {
				ProcessSendFatalAlert(new Alert(AlertDescription.InternalError, _handshakeSession.NegotiatedVersion));
				asyncHandshakeResult.SetComplete(new Exception("Connection closed because of local error", e));
			}
		}
		
		private void SendDataCallback(IAsyncResult asyncResult)
		{
			AsyncSendDataResult asyncSendDataResult = (AsyncSendDataResult)asyncResult.AsyncState;
			try {
				_recordStream.EndSend(asyncResult);
				asyncSendDataResult.SetComplete();
			} catch (AlertException ae) {
				ProcessSendFatalAlert(new Alert(ae.AlertDescription, _handshakeSession.NegotiatedVersion));
				asyncSendDataResult.SetComplete(new Exception("Connection closed because of local alert", ae));
			} catch (IOException) {
				asyncSendDataResult.SetComplete(new EndOfStreamException("Connection closed unexpectedly"));
			} catch (Exception e) {
				ProcessSendFatalAlert(new Alert(AlertDescription.InternalError, _handshakeSession.NegotiatedVersion));
				asyncSendDataResult.SetComplete(new Exception("Connection closed because of local error", e));
			}
		}
		
		private void ReceiveDataCallback(IAsyncResult asyncResult)
		{
			AsyncReceiveDataResult asyncReceiveDataResult = (AsyncReceiveDataResult)asyncResult.AsyncState;
			try {
				Record[] records = _recordStream.EndReceive(asyncResult);
				MemoryStream memStream = new MemoryStream();
				foreach (Record record in records) {
					_recordHandler.ProcessInputRecord(record);
					
					switch (record.Type) {
					case RecordType.ChangeCipherSpec:
						// FIXME: get the handshake result from somewhere
						//ProcessChangeCipherSpecRecord(record, asyncHandshakeResult);
						break;
					case RecordType.Alert:
						ProcessAlertRecord(record, asyncReceiveDataResult);
						break;
					case RecordType.Handshake:
						// FIXME: get the handshake result from somewhere
						//ProcessHandshakeRecord(record, asyncHandshakeResult);
						break;
					case RecordType.Data:
						memStream.Write(record.Fragment, 0, record.Fragment.Length);
						break;
					default:
						ProcessUnknownRecord(record, asyncReceiveDataResult);
						break;
					}
				}
				asyncReceiveDataResult.SetComplete(memStream.ToArray());
			} catch (AlertException ae) {
				ProcessSendFatalAlert(new Alert(ae.AlertDescription, _handshakeSession.NegotiatedVersion));
				asyncReceiveDataResult.SetComplete(new Exception("Connection closed because of local alert", ae));
			} catch (IOException) {
				asyncReceiveDataResult.SetComplete(new EndOfStreamException("Connection closed unexpectedly"));
			} catch (Exception e) {
				ProcessSendFatalAlert(new Alert(AlertDescription.InternalError, _handshakeSession.NegotiatedVersion));
				asyncReceiveDataResult.SetComplete(new Exception("Connection closed because of local error", e));
			}
		}
		
		
		
		private void ProcessChangeCipherSpecRecord(Record record, AsyncHandshakeResult asyncHandshakeResult)
		{
			if (record.Fragment.Length != 1 || record.Fragment[0] != 0x01) {
				throw new AlertException(AlertDescription.IllegalParameter,
				                         "Received an invalid ChangeCipherSpec record");
			}
			
			// NOTE: keep this before recordHandler.ChangeLocalState since it may generate masterSecret
			_handshakeSession.RemoteChangeCipherSpec();
			
			// Change cipher suite in record handler and handle it in handshake session
			_recordHandler.SetCipherSuite(_handshakeSession.CipherSuite, _handshakeSession.ConnectionState);
			_recordHandler.ChangeRemoteState();
			
			// Read the finished message after changing cipher spec
			_recordStream.BeginReceive(new AsyncCallback(ReceiveHandshakeCallback), asyncHandshakeResult);
		}
		
		private void ProcessSendChangeCipherSpec(AsyncHandshakeResult asyncHandshakeResult)
		{
			// Create the change cipher spec protocol packet
			// NOTE: this has to be before recordHandler.ChangeLocalState since it uses the old state
			Record record = new Record(RecordType.ChangeCipherSpec,
			                           _handshakeSession.NegotiatedVersion,
			                           new byte[] { 0x01 });
			_recordHandler.ProcessOutputRecord(record);
			
			// NOTE: keep this before recordHandler.ChangeLocalState since it may generate masterSecret
			_handshakeSession.LocalChangeCipherSpec();
			
			// Change cipher suite in record handler and handle it in handshake session
			_recordHandler.SetCipherSuite(_handshakeSession.CipherSuite, _handshakeSession.ConnectionState);
			_recordHandler.ChangeLocalState();
			
			// Send the change cipher spec protocol packet
			_recordStream.BeginSend(new Record[] { record }, new AsyncCallback(SendHandshakeCallback), asyncHandshakeResult);
		}
		
		private void ProcessAlertRecord(Record record, AsyncGenericResult asyncGenericResult)
		{
			// TODO: Received an alert, handle correctly
			Alert alert = new Alert(record.Fragment);
			Console.WriteLine("Received an alert: " + alert.Description);
			if (alert.Level == AlertLevel.Fatal) {
				// Fatal alerts don't need close notify
				_recordStream.Close();
				asyncGenericResult.SetComplete(new Exception("Received a fatal alert"));
				return;
			}
		}
		
		private void ProcessSendFatalAlert(Alert alert)
		{
			try {
				// Create and encrypt the alert record
				Record record = new Record(RecordType.Alert, _handshakeSession.NegotiatedVersion, alert.GetBytes());
				_recordHandler.ProcessOutputRecord(record);
				
				// Attempt sending the alert record
				_recordStream.Send(new Record[] { record });
				_recordStream.Flush();
				_recordStream.Close();
			} catch (Exception) {}
		}
		
		private void ProcessHandshakeRecord(Record record, AsyncHandshakeResult asyncHandshakeResult)
		{
			// Process each handshake message included in this record fragment separately
			HandshakeMessage[] msgs = _handshakePacketizer.ProcessHandshakeRecord(_handshakeSession.NegotiatedVersion, record);
			for (int i=0; i<msgs.Length; i++) {
				_handshakeSession.ProcessMessage(msgs[i]);
			}
			
			// Continue processing handshake by attempting to send packets
			ProcessSendHandshakePacket(asyncHandshakeResult);
		}
		
		private void ProcessSendHandshakePacket(AsyncHandshakeResult asyncHandshakeResult)
		{
			HandshakeMessage[] messages = _handshakeSession.GetOutputMessages();
			Record[] records = _handshakePacketizer.ProcessHandshakeMessages(_handshakeSession.NegotiatedVersion, messages, _recordStream.MaximumFragmentLength);
			if (records.Length > 0) {
				// Encrypt the handshake records
				for (int i=0; i<records.Length; i++) {
					_recordHandler.ProcessOutputRecord(records[i]);
				}
				_recordStream.BeginSend(records, new AsyncCallback(SendHandshakeCallback), asyncHandshakeResult);
			} else {
				if (_handshakeSession.State == HandshakeState.Finished) {
					// Handshake finished, mark result as complete
					asyncHandshakeResult.SetComplete();
				} else if (_handshakeSession.State == HandshakeState.SendChangeCipherSpec) {
					ProcessSendChangeCipherSpec(asyncHandshakeResult);
				} else {
					// Handshake not finished, receive the next handshake packet
					_recordStream.BeginReceive(new AsyncCallback(ReceiveHandshakeCallback), asyncHandshakeResult);
				}
			}
		}
		
		private void ProcessUnknownRecord(Record record, AsyncGenericResult asyncGenericResult)
		{
		}
	}
}

