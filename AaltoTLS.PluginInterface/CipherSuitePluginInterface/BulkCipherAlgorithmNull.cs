//
// AaltoTLS.PluginInterface.BulkCipherAlgorithmNull
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

namespace AaltoTLS.PluginInterface
{
	internal class NullCryptoTransform : ICryptoTransform
	{
		private bool _disposed = false;
		
		public bool CanReuseTransform { get { return true; } }
		public bool CanTransformMultipleBlocks { get { return true; } }
		public int InputBlockSize { get { return 1; } }
		public int OutputBlockSize { get { return 1; } }
		
		public int TransformBlock(byte[] inputBuffer,
		                          int inputOffset,
		                          int inputCount,
		                          byte[] outputBuffer,
		                          int outputOffset)
		{
			if (_disposed) {
				throw new ObjectDisposedException(GetType().FullName);
			}
			
			Buffer.BlockCopy(inputBuffer, inputOffset,
			                 outputBuffer, outputOffset,
			                 inputCount);
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
			Buffer.BlockCopy(inputBuffer, inputOffset, ret, 0, inputCount);
			return ret;
		}

		public void Dispose()
		{
			_disposed = true;
		}
	}
	
	public class BulkCipherAlgorithmNull : BulkCipherAlgorithm
	{
		public override int KeySize
		{
			get { return 0; }
		}

		public override int BlockSize
		{
			get { return 1; }
		}
		
		public override int Strength
		{
			get { return 0; }
		}

		public override BulkCipherAlgorithmType Type
		{
			get { return BulkCipherAlgorithmType.Stream; }
		}
		
		public override bool SupportsProtocolVersion(ProtocolVersion version)
		{
			return true;
		}

		public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			return new NullCryptoTransform();
		}

		public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV, byte[] additional)
		{
			return new NullCryptoTransform();
		}
	}
}
