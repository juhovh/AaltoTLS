//
// AaltoTLS.RecordLayer.RecordHandler
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
using System.Security.Cryptography;

using AaltoTLS.Alerts;
using AaltoTLS.PluginInterface;

namespace AaltoTLS.RecordLayer
{
	public class RecordHandler
	{
		private bool _isClient;
		
		private CipherSuite _nextCipherSuite;
		private KeyBlock _nextKeyBlock;
		
		private CipherSuite _outputCipherSuite;
		private CipherSuite _inputCipherSuite;
		private KeyBlock _outputKeyBlock;
		private KeyBlock _inputKeyBlock;
		
		private UInt16 _outputEpoch;
		private UInt64 _outputSequenceNumber;
		private UInt16 _inputEpoch;
		private UInt64 _inputSequenceNumber;

		KeyedHashAlgorithm _outputHasher;
		KeyedHashAlgorithm _inputHasher;
		ICryptoTransform _encryptor;
		ICryptoTransform _decryptor;

		// Helpers for AEAD
		byte[] _outputKey;
		byte[] _inputKey;
		byte[] _outputFixedIV;
		byte[] _inputFixedIV;
		byte[] _outputRecordIV;
		
		public RecordHandler(ProtocolVersion version, bool isClient)
		{
			_isClient = isClient;

			// Start with NULL cipher suite and key block
			_nextCipherSuite = new CipherSuite(version);
			_nextKeyBlock = new KeyBlock();
			
			// Initialize all the other variables
			ChangeLocalState();
			ChangeRemoteState();
			
			_inputEpoch = 0;
			_outputEpoch = 0;
		}
		
		public void SetCipherSuite(CipherSuite cipherSuite, ConnectionState connectionState)
		{
			// Get master secret from connectionState
			byte[] masterSecret = connectionState.MasterSecret;
			
			// Generate seed for changing cipher suite
			byte[] seed = new byte[64];
			Array.Copy(connectionState.ServerRandom, 0, seed, 0, 32);
			Array.Copy(connectionState.ClientRandom, 0, seed, 32, 32);
			
			_nextCipherSuite = cipherSuite;
			_nextKeyBlock = new KeyBlock(cipherSuite, masterSecret, seed);
		}
		
		public void ChangeLocalState()
		{
			_outputCipherSuite = _nextCipherSuite;
			_outputKeyBlock = _nextKeyBlock;
			_outputSequenceNumber = 0;
			_outputEpoch++;

			if (_isClient) {
				_outputHasher = _outputCipherSuite.MACAlgorithm.CreateHasher(_outputKeyBlock.ClientWriteMACKey);
				_encryptor = _outputCipherSuite.BulkCipherAlgorithm.CreateEncryptor(_outputKeyBlock.ClientWriteKey,
				                                                                    _outputKeyBlock.ClientWriteIV);

				_outputKey = _outputKeyBlock.ClientWriteKey;
				_outputFixedIV = _outputKeyBlock.ClientWriteIV;
			} else {
				_outputHasher = _outputCipherSuite.MACAlgorithm.CreateHasher(_outputKeyBlock.ServerWriteMACKey);
				_encryptor = _outputCipherSuite.BulkCipherAlgorithm.CreateEncryptor(_outputKeyBlock.ServerWriteKey,
				                                                                    _outputKeyBlock.ServerWriteIV);

				_outputKey = _outputKeyBlock.ServerWriteKey;
				_outputFixedIV = _outputKeyBlock.ServerWriteIV;
			}
			
			// IMPORTANT: This needs to be XORed with ie. sequence number to make sure it is unique
			_outputRecordIV = new byte[_outputCipherSuite.BulkCipherAlgorithm.RecordIVLength];
			RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
			rngCsp.GetBytes(_outputRecordIV);
		}
		
		public void ChangeRemoteState()
		{
			_inputCipherSuite = _nextCipherSuite;
			_inputKeyBlock = _nextKeyBlock;
			_inputSequenceNumber = 0;
			_inputEpoch++;
			
			if (_isClient) {
				_inputHasher = _inputCipherSuite.MACAlgorithm.CreateHasher(_inputKeyBlock.ServerWriteMACKey);
				_decryptor = _inputCipherSuite.BulkCipherAlgorithm.CreateDecryptor(_inputKeyBlock.ServerWriteKey,
				                                                                   _inputKeyBlock.ServerWriteIV);

				_inputKey = _inputKeyBlock.ServerWriteKey;
				_inputFixedIV = _inputKeyBlock.ServerWriteIV;
			} else {
				_inputHasher = _inputCipherSuite.MACAlgorithm.CreateHasher(_inputKeyBlock.ClientWriteMACKey);
				_decryptor = _inputCipherSuite.BulkCipherAlgorithm.CreateDecryptor(_inputKeyBlock.ClientWriteKey,
				                                                                   _inputKeyBlock.ClientWriteIV);

				_inputKey = _inputKeyBlock.ClientWriteKey;
				_inputFixedIV = _inputKeyBlock.ClientWriteIV;
			}
		}
		
		public void ProcessOutputRecord(Record output)
		{
			// Construct the sequence number correctly
			UInt64 seqNum = _outputSequenceNumber;
			if (output.Version.IsUsingDatagrams) {
				if ((_outputSequenceNumber >> 48) != 0) {
					// TODO: need renegotiation, throw Exception?
				}
				seqNum = (((UInt64)_outputEpoch) << 48) | _outputSequenceNumber;
			}
			
			// In case of AEAD we need to create a new encryptor for each record
			byte[] nonceExplicit = new byte[0];
			if (_outputCipherSuite.BulkCipherAlgorithm.Type == BulkCipherAlgorithmType.AEAD) {
				_encryptor = CreateAEADEncryptor(_outputCipherSuite, output, _outputKey, _outputFixedIV, _outputRecordIV, seqNum, out nonceExplicit);
			}

			CompressRecord(output);
			GenerateMAC(_outputCipherSuite, output, seqNum, _outputHasher);
			GeneratePadding(_outputCipherSuite, output);
			EncryptRecord(_outputCipherSuite, output, _encryptor, nonceExplicit);
			
			// If we're running DTLS, set epoch and seqnum
			if (output.Version.IsUsingDatagrams) {
				output.Epoch = _outputEpoch;
				output.SequenceNumber = _outputSequenceNumber;
			}

			// Update the output sequence number
			_outputSequenceNumber++;
		}

		public bool ProcessInputRecord(Record input)
		{
			// If we're running DTLS, ignore packets with incorrect epoch
			if (input.Version.IsUsingDatagrams && input.Epoch != _inputEpoch) {
				return false;
			}
			
			// If we're running DTLS, get epoch and seqnum
			UInt64 seqNum = _inputSequenceNumber;
			if (input.Version.IsUsingDatagrams) {
				seqNum = (((UInt64)input.Epoch) << 48) | input.SequenceNumber;
			}

			// In case of AEAD we need to create a new decryptor for each record
			if (_inputCipherSuite.BulkCipherAlgorithm.Type == BulkCipherAlgorithmType.AEAD) {
				_decryptor = CreateAEADDecryptor(_inputCipherSuite, input, _inputKey, _inputFixedIV, seqNum);
			}
			
			bool decryptValid = DecryptRecord(_inputCipherSuite, input, _decryptor);
			bool paddingValid = RemovePadding(_inputCipherSuite, input);
			bool MACValid = RemoveMAC(_inputCipherSuite, input, seqNum, _inputHasher);
			DecompressRecord(input);

			if (!decryptValid || !paddingValid || !MACValid) {
				string message = "Invalid MAC: decrypt " + decryptValid + " padding " + paddingValid + " MAC " + MACValid;
				throw new AlertException(AlertDescription.BadRecordMAC, message);
			}

			_inputSequenceNumber++;
			return true;
		}





		private static void CompressRecord(Record record)
		{
			/* TODO: Should handle compression here */
		}

		private static void DecompressRecord(Record record)
		{
			/* TODO: Should handle decompression here */
		}



		private static void GeneratePadding(CipherSuite cipherSuite, Record record)
		{
			BulkCipherAlgorithmType cipherType = cipherSuite.BulkCipherAlgorithm.Type;

			if (cipherType == BulkCipherAlgorithmType.Block) {
				int blockSize = cipherSuite.BulkCipherAlgorithm.BlockSize;

				// Add the required padding to the end of fragment if necessary,
				// minimum padding 1 bytes, the length byte of padding itself
				int paddingLength = blockSize - (record.Fragment.Length % blockSize);
				if (record.Version.HasVariablePadding) {
					// Add 0-1 additional blocks
					int extra = (new System.Random()).Next(2);
					if (paddingLength + extra*blockSize < 256) {
						paddingLength += extra*blockSize;
					}
				}

				// Add the actual padding bytes here
				byte[] padding = new byte[paddingLength];
				if (record.Version == ProtocolVersion.SSL3_0) {
					RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
					rngCsp.GetBytes(padding);
					padding[padding.Length-1] = (byte) (padding.Length-1);
				} else {
					for (int i=1; i<=padding.Length; i++) {
						padding[padding.Length-i] = (byte) (padding.Length-1);
					}
				}

				byte[] fragment = new byte[record.Fragment.Length + padding.Length];
				Buffer.BlockCopy(record.Fragment, 0, fragment, 0, record.Fragment.Length);
				Buffer.BlockCopy(padding, 0, fragment, record.Fragment.Length, padding.Length);
				record.Fragment = fragment;
			}
		}

		private static bool RemovePadding(CipherSuite cipherSuite, Record record)
		{
			BulkCipherAlgorithmType cipherType = cipherSuite.BulkCipherAlgorithm.Type;
			bool verified = true;

			if (cipherType == BulkCipherAlgorithmType.Block) {
				// Get padding bytes from the end of the fragment
				int padding = record.Fragment[record.Fragment.Length-1]+1;
					
				// Verify the correctness of padding
				if (padding > record.Fragment.Length) {
					verified = false;
				} else {
					verified = true;
					if (record.Version.HasVerifiablePadding) {
						for (int i=1; i<=padding; i++) {
							if (record.Fragment[record.Fragment.Length-i] != (padding-1)) {
								verified = false;
							}
						}
					}
					
					// Remove padding from the fragment data
					if (verified) {
						byte[] fragment = new byte[record.Fragment.Length-padding];
						Buffer.BlockCopy(record.Fragment, 0, fragment, 0, fragment.Length);
						record.Fragment = fragment;
					}
				}
			}

			return verified;
		}



		private static byte[] GetAdditionalBytes(UInt64 seqNum, byte type, ProtocolVersion version, int length)
		{
			byte[] seqData = BitConverter.GetBytes(seqNum);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(seqData);
			}

			byte[] additional;
			if (version == ProtocolVersion.SSL3_0) {
				// With SSL3 should not include version information
				additional = new byte[11];
				Buffer.BlockCopy(seqData, 0, additional, 0, 8);
				additional[8]  = (byte) (type);
				additional[9]  = (byte) (length >> 8);
				additional[10] = (byte) (length);
			} else {
				// Normal TLS additional bytes to be used
				additional = new byte[13];
				Buffer.BlockCopy(seqData, 0, additional, 0, 8);
				additional[8]  = (byte) (type);
				additional[9]  = version.Major;
				additional[10] = version.Minor;
				additional[11] = (byte) (length >> 8);
				additional[12] = (byte) (length);
			}
			return additional;
		}

		private static void GenerateMAC(CipherSuite cipherSuite, Record record, UInt64 seqNum, KeyedHashAlgorithm hasher)
		{
			BulkCipherAlgorithmType cipherType = cipherSuite.BulkCipherAlgorithm.Type;
			
			if (cipherType == BulkCipherAlgorithmType.Stream || cipherType == BulkCipherAlgorithmType.Block) {
				byte[] additional = GetAdditionalBytes(seqNum, record.Type, record.Version, record.Fragment.Length);

				// Calculate the MAC of the packet
				hasher.Initialize();
				hasher.TransformBlock(additional, 0, additional.Length, additional, 0);
				hasher.TransformFinalBlock(record.Fragment, 0, record.Fragment.Length);
				byte[] MAC = hasher.Hash;

				/* Add MAC to the end of the fragment */
				byte[] fragment = new byte[record.Fragment.Length + MAC.Length];
				Buffer.BlockCopy(record.Fragment, 0, fragment, 0, record.Fragment.Length);
				Buffer.BlockCopy(MAC, 0, fragment, record.Fragment.Length, MAC.Length);
				record.Fragment = fragment;
			}
		}
		
		private static bool RemoveMAC(CipherSuite cipherSuite, Record record, UInt64 seqNum, KeyedHashAlgorithm hasher)
		{
			BulkCipherAlgorithmType cipherType = cipherSuite.BulkCipherAlgorithm.Type;
			bool verified = true;

			if (cipherType == BulkCipherAlgorithmType.Stream || cipherType == BulkCipherAlgorithmType.Block) {
				int MACLength = cipherSuite.MACAlgorithm.HashSize;
				if (record.Fragment.Length < MACLength) {
					verified = false;
				} else {
					// Allocate a fragment without the MAC value
					byte[] newFragment = new byte[record.Fragment.Length - MACLength];
					Buffer.BlockCopy(record.Fragment, 0, newFragment, 0, newFragment.Length);

					// Calculate the MAC again for new fragment
					byte[] oldFragment = record.Fragment;
					record.Fragment = newFragment;
					GenerateMAC(cipherSuite, record, seqNum, hasher);
	
					// Compare our MAC value with theirs
					verified = true;
					for (int i=1; i<=MACLength; i++) {
						if (oldFragment[oldFragment.Length-i] != record.Fragment[record.Fragment.Length-i]) {
							verified = false;
						}
					}

					// Replace fragment with the one without MAC value
					record.Fragment = newFragment;
				}
			}

			return verified;
		}



		private static byte[] TransformRecordBytes(BulkCipherAlgorithmType cipherType, ICryptoTransform transform, byte[] input)
		{
			if (cipherType != BulkCipherAlgorithmType.AEAD) {
				// In case of non-AEAD cipher algorithm, check that data matches block size
				if (input.Length % transform.InputBlockSize != 0) {
					throw new Exception("Input data size doesn't match block size");
				}
			}

			int blockCount = input.Length / transform.InputBlockSize;
			if (cipherType == BulkCipherAlgorithmType.AEAD) {
				// Make sure there is enough data at TransformFinalBlock, because
				// decryption requires that the authentication tag is present
				if (blockCount > 0) {
					blockCount--;
				}
			}

			byte[] output = new byte[blockCount * transform.OutputBlockSize];
			if (transform.CanTransformMultipleBlocks) {
				transform.TransformBlock(input, 0, blockCount*transform.InputBlockSize, output, 0);
			} else {
				for (int i=0; i<blockCount; i++) {
					transform.TransformBlock(input, i*transform.InputBlockSize,
					                         transform.InputBlockSize,
					                         output, i*transform.OutputBlockSize);
				}
			}

			if (cipherType == BulkCipherAlgorithmType.AEAD) {
				int currentPosition = blockCount*transform.InputBlockSize;

				// Transfer the last block when encrypting or authentication tag when decrypting
				byte[] finalBytes = transform.TransformFinalBlock(input, currentPosition, input.Length-currentPosition);
				if (finalBytes == null) {
					return null;
				} else if (finalBytes.Length > 0) {
					byte[] finalOutput = new byte[output.Length + finalBytes.Length];
					Buffer.BlockCopy(output, 0, finalOutput, 0, output.Length);
					Buffer.BlockCopy(finalBytes, 0, finalOutput, output.Length, finalBytes.Length);
					output = finalOutput;
				}
			}

			return output;
		}
		
		private static byte[] GenerateAEADNonceExplicit(byte[] recordIV, UInt64 seqNum)
		{
			// Generate explicit part of defined length
			byte[] nonceExplicit = new byte[recordIV.Length];

			// Copy the sequence number to the end of the explicit part
			byte[] seqData = BitConverter.GetBytes(seqNum);
			if (BitConverter.IsLittleEndian) {
				Array.Reverse(seqData);
			}
			int seqSrcIdx = Math.Max(0, seqData.Length-nonceExplicit.Length);
			int seqDstIdx = Math.Max(0, nonceExplicit.Length-seqData.Length);
			int seqLength = Math.Min(seqData.Length, nonceExplicit.Length);
			Buffer.BlockCopy(seqData, seqSrcIdx, nonceExplicit, seqDstIdx, seqLength);
			
			// XOR with the random recordIV and return
			for (int i=0; i<nonceExplicit.Length; i++) {
				nonceExplicit[i] ^= recordIV[i];
			}
			return nonceExplicit;
		}

		private static byte[] GenerateAEADNonce(byte[] nonceImplicit, byte[] nonceExplicit)
		{
			byte[] nonce = new byte[nonceImplicit.Length + nonceExplicit.Length];
			Buffer.BlockCopy(nonceImplicit, 0, nonce, 0, nonceImplicit.Length);
			Buffer.BlockCopy(nonceExplicit, 0, nonce, nonceImplicit.Length, nonceExplicit.Length);
			return nonce;
		}
		
		private static ICryptoTransform CreateAEADEncryptor(CipherSuite cipherSuite, Record record,
		                                                    byte[] key, byte[] fixedIV, byte[] recordIV,
		                                                    UInt64 seqNum, out byte[] nonceExplicit)
		{
			// Construct the nonce for AEAD cipher
			nonceExplicit = GenerateAEADNonceExplicit(recordIV, seqNum);
			byte[] nonce = GenerateAEADNonce(fixedIV, nonceExplicit);

			// Construct the additional bytes for AEAD cipher
			byte[] additional = GetAdditionalBytes(seqNum, record.Type, record.Version, record.Fragment.Length);
			
			return cipherSuite.BulkCipherAlgorithm.CreateEncryptor(key, nonce, additional);
		}

		private static void EncryptRecord(CipherSuite cipherSuite, Record record, ICryptoTransform cipher, byte[] nonceExplicit)
		{
			BulkCipherAlgorithmType cipherType = cipherSuite.BulkCipherAlgorithm.Type;
			int recordIVLength = cipherSuite.BulkCipherAlgorithm.RecordIVLength;

			// Add explicit IV if required by protocol version
			if (cipherType == BulkCipherAlgorithmType.Block && record.Version.HasExplicitIV) {
				byte[] explicitIV = new byte[recordIVLength];
				RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
				rngCsp.GetBytes(explicitIV);

				// Replace the fragment with a new fragment including explicit IV
				byte[] fragment = new byte[explicitIV.Length + record.Fragment.Length];
				Buffer.BlockCopy(explicitIV, 0, fragment, 0, explicitIV.Length);
				Buffer.BlockCopy(record.Fragment, 0, fragment, explicitIV.Length, record.Fragment.Length);
				record.Fragment = fragment;
			}

			// Replace the unencrypted fragment with the encrypted fragment
			record.Fragment = TransformRecordBytes(cipherType, cipher, record.Fragment);
			
			// Add explicit part of the nonce if using AEAD
			if (cipherType == BulkCipherAlgorithmType.AEAD) {
				byte[] fragment = new byte[nonceExplicit.Length + record.Fragment.Length];
				Buffer.BlockCopy(nonceExplicit, 0, fragment, 0, nonceExplicit.Length);
				Buffer.BlockCopy(record.Fragment, 0, fragment, nonceExplicit.Length, record.Fragment.Length);
				record.Fragment = fragment;
			}
		}

		private static ICryptoTransform CreateAEADDecryptor(CipherSuite cipherSuite, Record record,
		                                                    byte[] key, byte[] fixedIV, UInt64 seqNum)
		{
			// Get the explicit nonce from the beginning of fragment
			int recordIVLength = cipherSuite.BulkCipherAlgorithm.RecordIVLength;
			byte[] nonceExplicit = new byte[recordIVLength];
			Buffer.BlockCopy(record.Fragment, 0, nonceExplicit, 0, nonceExplicit.Length);
			
			// Construct the nonce for AEAD cipher
			byte[] nonce = GenerateAEADNonce(fixedIV, nonceExplicit);

			// Construct the additional bytes for AEAD cipher
			int compressedLength = record.Fragment.Length - recordIVLength - cipherSuite.BulkCipherAlgorithm.AuthenticationTagSize;
			byte[] additional = GetAdditionalBytes(seqNum, record.Type, record.Version, compressedLength);

			return cipherSuite.BulkCipherAlgorithm.CreateDecryptor(key, nonce, additional);
		}

		private static bool DecryptRecord(CipherSuite cipherSuite, Record record, ICryptoTransform cipher)
		{
			BulkCipherAlgorithmType cipherType = cipherSuite.BulkCipherAlgorithm.Type;
			int recordIVLength = cipherSuite.BulkCipherAlgorithm.RecordIVLength;
			
			if (cipherType == BulkCipherAlgorithmType.AEAD) {
				int authTagSize = cipherSuite.BulkCipherAlgorithm.AuthenticationTagSize;
				
				// Remove explicit nonce from the beginning of the fragment
				byte[] tmp = new byte[record.Fragment.Length-recordIVLength];
				Buffer.BlockCopy(record.Fragment, recordIVLength, tmp, 0, tmp.Length);
				record.Fragment = tmp;
				
				// Make sure there is enough data for the authentication tag
				if (record.Fragment.Length < authTagSize) {
					return false;
				}
			}
			
			// Replace the encrypted fragment with the decrypted fragment
			byte[] fragment = TransformRecordBytes(cipherType, cipher, record.Fragment);
			if (fragment == null) {
				return false;
			}
			record.Fragment = fragment;
			
			// Remove explicit IV from the beginning of the fragment if necessary
			if (cipherType == BulkCipherAlgorithmType.Block && record.Version.HasExplicitIV) {
				fragment = new byte[record.Fragment.Length-recordIVLength];
				Buffer.BlockCopy(record.Fragment, recordIVLength, fragment, 0, record.Fragment.Length-recordIVLength);
				record.Fragment = fragment;
			}

			return true;
		}
	}
}
