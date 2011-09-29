//
// AaltoTLS.RecordLayer.TLSRecordStream
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
using System.Collections.Generic;

namespace AaltoTLS.RecordLayer
{
	public class TLSRecordStream : RecordStream
	{
		private const int MAX_FRAGMENT_SIZE = 16384;
		private const int MAX_RECORD_SIZE = 5+16384+2048;
		
		private Stream _innerStream;
		
		private Object _receiveLock = new Object();
		private List<AsyncReceiveRecordsResult> _receiveQueue = new List<AsyncReceiveRecordsResult>();
		private bool _receiving;
		
		private Object _sendLock = new Object();
		private List<AsyncSendRecordsResult> _sendQueue = new List<AsyncSendRecordsResult>();
		private bool _sending;
		
		private byte[] _inputBuffer;
		private int _inputBufferCount;
		
		public TLSRecordStream(Stream innerStream)
		{
			_innerStream = innerStream;
			
			_inputBuffer = new byte[MAX_RECORD_SIZE];
			_inputBufferCount = 0;
		}
		
		public override int MaximumFragmentLength {
			get { return MAX_FRAGMENT_SIZE; }
		}
		
		public override IAsyncResult BeginReceive(AsyncCallback requestCallback, Object state)
		{
			AsyncReceiveRecordsResult asyncReceiveResult = new AsyncReceiveRecordsResult(requestCallback, state);
			StartReceive(asyncReceiveResult);
			return asyncReceiveResult;
		}
		
		public override IAsyncResult BeginSend(Record[] records, AsyncCallback requestCallback, Object state)
		{
			if (records == null) {
				throw new ArgumentNullException("records");
			}
			
			// Make sure fragments are not too long
			AsyncSendRecordsResult asyncSendResult = new AsyncSendRecordsResult(records, requestCallback, state);
			foreach (Record record in records) {
				if (record.Fragment.Length > MAX_RECORD_SIZE) {
					asyncSendResult.SetComplete(new RecordTooLargeException("Trying to send a too large fragment: " + record.Fragment.Length));
					return asyncSendResult;
				}
			}
			
			// Start sending the records
			StartSend(asyncSendResult);
			return asyncSendResult;
		}
		
		public override Record[] EndReceive(IAsyncResult asyncResult)
		{
			AsyncReceiveRecordsResult asyncReceiveResult = (AsyncReceiveRecordsResult)asyncResult;
			if (!asyncReceiveResult.IsCompleted) {
				asyncReceiveResult.AsyncWaitHandle.WaitOne();
			}
			if (asyncReceiveResult.CompletedWithException) {
				throw asyncReceiveResult.AsyncException;
			}
			return asyncReceiveResult.AsyncResult;
		}
		
		public override void EndSend(IAsyncResult asyncResult)
		{
			AsyncSendRecordsResult asyncSendResult = (AsyncSendRecordsResult)asyncResult;
			if (!asyncSendResult.IsCompleted) {
				asyncSendResult.AsyncWaitHandle.WaitOne();
			}
			if (asyncSendResult.CompletedWithException) {
				throw asyncSendResult.AsyncException;
			}
		}
		
		public override void Flush()
		{
			_innerStream.Flush();
		}
		
		public override void Close()
		{
			_innerStream.Close();
		}
		
		private void ReadCallback(IAsyncResult asyncResult)
		{
			AsyncReceiveRecordsResult asyncReadResult = (AsyncReceiveRecordsResult)asyncResult.AsyncState;
			try {
				int readBytes = _innerStream.EndRead(asyncResult);
				if (readBytes == 0) {
					throw new EndOfStreamException("Connection closed while reading TLS record");
				}
				_inputBufferCount += readBytes;
				
				// We require at least 5 bytes of header
				if (_inputBufferCount < 5) {
					_innerStream.BeginRead(_inputBuffer,
					                       _inputBufferCount,
					                       5-_inputBufferCount,
					                       new AsyncCallback(ReadCallback),
					                       asyncReadResult);
					return;
				}
				
				// We require the fragment bytes
				int fragmentLength = (_inputBuffer[3] << 8) | _inputBuffer[4];
				if (5+fragmentLength > _inputBuffer.Length) {
					throw new RecordTooLargeException("Received TLS record fragment size too large");
				} else if (_inputBufferCount < 5+fragmentLength) {
					_innerStream.BeginRead(_inputBuffer,
					                       _inputBufferCount,
					                       5+fragmentLength-_inputBufferCount,
					                       new AsyncCallback(ReadCallback),
					                       asyncReadResult);
					return;
				}
				
				// Construct the TLSRecord returned as result
				Record record = new Record(_inputBuffer);
				Buffer.BlockCopy(_inputBuffer, 5, record.Fragment, 0, fragmentLength);
				_inputBufferCount = 0;
				
				// Complete the asynchronous read
				FinishReceive(true);
				asyncReadResult.AddRecord(record);
				asyncReadResult.SetComplete();
			} catch (Exception e) {
				FinishReceive(false);
				asyncReadResult.SetComplete(e);
			}
		}
		
		private void WriteCallback(IAsyncResult asyncResult)
		{
			AsyncSendRecordsResult asyncSendResult = (AsyncSendRecordsResult)asyncResult.AsyncState;
			try {
				_innerStream.EndWrite(asyncResult);
				
				// Check if send request has more bytes to send
				byte[] outputBuffer = asyncSendResult.GetRecords(0);
				if (outputBuffer.Length > 0) {
					_innerStream.BeginWrite(outputBuffer, 0, outputBuffer.Length,
				                            new AsyncCallback(WriteCallback),
				                            asyncSendResult);
					return;
				}
				
				FinishSend(true);
				asyncSendResult.SetComplete();
			} catch (Exception e) {
				FinishSend(false);
				asyncSendResult.SetComplete(e);
			}
		}
		
		private void StartReceive(AsyncReceiveRecordsResult asyncReceiveResult)
		{
			lock (_receiveLock) {
				if (_receiving) {
					// Receive in progress, add to queue
					if (asyncReceiveResult != null) {
						_receiveQueue.Add(asyncReceiveResult);
					}
					return;
				}
				
				if (asyncReceiveResult == null && _receiveQueue.Count > 0) {
					// Get first asyncReceiveResult in queue
					asyncReceiveResult = _receiveQueue[0];
					_receiveQueue.Remove(asyncReceiveResult);
				}
				
				if (asyncReceiveResult != null) {
					// Start reading the header
					_innerStream.BeginRead(_inputBuffer, 0, 5, new AsyncCallback(ReadCallback), asyncReceiveResult);
					_receiving = true;
				}
			}
		}
		
		private void FinishReceive(bool success)
		{
			lock (_receiveLock) {
				_receiving = false;
			}
			if (success) {
				// Check the receive queue for other requests
				StartReceive(null);
			}
		}
		
		private void StartSend(AsyncSendRecordsResult asyncSendResult)
		{
			lock (_sendLock) {
				if (_sending) {
					// Send in progress, add to queue
					if (asyncSendResult != null) {
						_sendQueue.Add(asyncSendResult);
					}
					return;
				} else if (asyncSendResult != null) {
					// No send in progress, insert to queue
					_sendQueue.Insert(0, asyncSendResult);
				}
				
				byte[] outputBuffer = new byte[0];
				while (outputBuffer.Length == 0 && _sendQueue.Count > 0) {
					// Get first asyncSendResult in queue
					asyncSendResult = _sendQueue[0];
					_sendQueue.Remove(asyncSendResult);
					
					// Get output buffer from record bytes
					outputBuffer = asyncSendResult.GetRecords(0);
					if (outputBuffer.Length == 0) {
						asyncSendResult.SetComplete();
						asyncSendResult = null;
					}
				}
				
				if (asyncSendResult != null && outputBuffer.Length > 0) {
					// Start sending the record
					_innerStream.BeginWrite(outputBuffer, 0, outputBuffer.Length,
				                            new AsyncCallback(WriteCallback),
				                            asyncSendResult);
					_sending = true;
				}
			}
		}
		
		private void FinishSend(bool success)
		{
			lock (_sendLock) {
				_sending = false;
			}
			if (success) {
				// Check the send queue for other requests
				StartSend(null);
			}
		}
	}
}
