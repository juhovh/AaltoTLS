//
// AaltoTLS.AsyncGenericResult
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
using System.Threading;

namespace AaltoTLS
{
	public class AsyncGenericResult : IAsyncResult
	{
		protected Object         resultLock;
		
		private bool             _isCompleted;
		private ManualResetEvent _waitHandle;

		private AsyncCallback    _requestCallback;
		private Object           _state;

		private Exception _asyncException;

		internal AsyncGenericResult(AsyncCallback requestCallback, Object state)
		{
			resultLock = new Object();
			
			_isCompleted = false;
			_waitHandle = new ManualResetEvent(false);
			
			_requestCallback = requestCallback;
			_state = state;
		}

		#region Methods required by IAsyncResult interface
		public bool IsCompleted {
			get { lock (resultLock) return _isCompleted; }
		}

		public WaitHandle AsyncWaitHandle {
			get { lock (resultLock) return _waitHandle; }
		}

		public Object AsyncState {
			get { return _state; }
		}

		public bool CompletedSynchronously {
			get { return false; }
		}
		#endregion

		public void SetComplete()
		{
			SetComplete(null);
		}

		public void SetComplete(Exception e)
		{
			lock (resultLock) {
				if (_isCompleted)
					return;

				_asyncException = e;
				_isCompleted = true;
				_waitHandle.Set();
			}
			if (_requestCallback != null) {
				_requestCallback.Invoke(this);
			}
		}

		public bool CompletedWithException {
			get {
				lock (resultLock) {
					return (_isCompleted && _asyncException != null);
				}
			}
		}

		public Exception AsyncException {
			get { lock (resultLock) return _asyncException; }
		}
	}
}
