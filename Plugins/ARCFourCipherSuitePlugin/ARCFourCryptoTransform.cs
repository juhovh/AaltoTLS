//
// ARCFourCryptoTransform
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
using System.Security.Cryptography;
using AaltoTLS.PluginInterface;

namespace ARCFourCipherSuitePlugin
{
	internal class ARCFourCryptoTransform : ICryptoTransform
	{
		private bool _disposed = false;

		private byte[] _key;
		private byte[] _permutation;
		private byte _index1;
		private byte _index2;

		public bool CanReuseTransform { get { return true; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return 1; } }
		public int OutputBlockSize { get { return 1; } }

		public ARCFourCryptoTransform(byte[] key)
		{
			_key = (byte[]) key.Clone();
			_permutation = new byte[256];
			Reset();
		}

		private void Reset()
		{
			for (int i=0; i<256; i++) {
				_permutation[i] = (byte) i;
			}
			_index1 = 0;
			_index2 = 0;

			for (int i=0, j=0; i<256; i++) {
				j = (j + _permutation[i] + _key[i % _key.Length]) % 256;

				byte tmp = _permutation[i];
				_permutation[i] = _permutation[j];
				_permutation[j] = tmp;
			}
		}

		public int TransformBlock(byte[] inputBuffer,
		                          int inputOffset,
		                          int inputCount,
		                          byte[] outputBuffer,
		                          int outputOffset)
		{
			if (_disposed) {
				throw new ObjectDisposedException(GetType().FullName);
			}

			for (int i=0; i<inputCount; i++) {
				_index1 = (byte) (_index1 + 1);
				_index2 = (byte) (_index2 + _permutation[_index1]);

				byte tmp = _permutation[_index1];
				_permutation[_index1] = _permutation[_index2];
				_permutation[_index2] = tmp;

				byte idx = (byte) (_permutation[_index1] + _permutation[_index2]);
				byte val = (byte) (inputBuffer[inputOffset+i] ^ _permutation[idx]);
				outputBuffer[outputOffset+i] = val;
			}

			return inputCount;
		}

		public byte[] TransformFinalBlock(byte[] inputBuffer,
		                                  int inputOffset,
		                                  int inputCount)
		{
			if (_disposed) {
				throw new ObjectDisposedException(GetType().FullName);
			}

			byte[] ret = new byte[inputCount];
			TransformBlock(inputBuffer, inputOffset, inputCount, ret, 0);
			Reset();

			return ret;
		}

		public void Dispose()
		{
			_disposed = true;
		}
	}
}
