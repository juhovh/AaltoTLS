//
// AaltoTLS.PluginInterface.CipherSuitePluginManager
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
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AaltoTLS.PluginInterface
{
	public class CipherSuitePluginManager
	{
		CipherSuitePlugin[] _plugins;

		public CipherSuitePluginManager(string path)
		{
			_plugins = FindCipherSuitePlugins(path);
		}
		
		public CertificatePrivateKey GetPrivateKey(byte[] keyData)
		{
			foreach (CipherSuitePlugin plugin in _plugins) {
				string[] signatureIDs = plugin.SupportedSignatureAlgorithms;
				foreach (string id in signatureIDs) {
					SignatureAlgorithm signatureAlgorithm = plugin.GetSignatureAlgorithm(id);
					CertificatePrivateKey privateKey = signatureAlgorithm.ImportPrivateKey(keyData);
					if (privateKey != null) {
						return privateKey;
					}
				}
			}
			return null;
		}
		
		public UInt16[] GetSupportedSignatureAndHashAlgorithms()
		{
			List<UInt16> sighashes = new List<UInt16>();
			foreach (CipherSuitePlugin plugin in _plugins) {
				string[] sigIDs = plugin.SupportedSignatureAlgorithms;
				foreach (string sigID in sigIDs) {
					SignatureAlgorithm sig = plugin.GetSignatureAlgorithm(sigID);
					if (sig == null)
						continue;
					
					byte sigType = sig.SignatureAlgorithmType;
					if (sigType == 0) {
						// Ignore anonymous
						continue;
					}
					
					// TODO: Now scans from sha512 to md5, should be configurable?
					for (byte b=6; b>0; b--) {
						if (!sig.SupportsHashAlgorithmType(b))
							continue;
						sighashes.Add((UInt16)((b << 8) | sigType));
					}
				}
			}
			return sighashes.ToArray();
		}
		
		public UInt16[] GetSupportedCipherSuiteIDs(ProtocolVersion version, X509Certificate certificate, bool includeAnonymous)
		{
			List<UInt16> suites = new List<UInt16>();
			foreach (CipherSuitePlugin plugin in _plugins) {
				UInt16[] suiteIDs = plugin.SupportedCipherSuites;
				foreach (UInt16 id in suiteIDs) {
					CipherSuite cipherSuite = GetCipherSuite(version, id);
					if (cipherSuite == null) {
						continue;
					}
					if (cipherSuite.IsAnonymous) {
						if (includeAnonymous) {
							suites.Add(id);
						}
						continue;
					}
					
					string keyexAlg = cipherSuite.KeyExchangeAlgorithm.CertificateKeyAlgorithm;
					string sigAlg = cipherSuite.SignatureAlgorithm.CertificateKeyAlgorithm;
					
					if (keyexAlg != null && !keyexAlg.Equals(certificate.GetKeyAlgorithm())) {
						continue;
					}
					if (sigAlg != null && !sigAlg.Equals(certificate.GetKeyAlgorithm())) {
						continue;
					}
					suites.Add(id);
				}
			}
			return suites.ToArray();
		}
		
		public SignatureAlgorithm GetSignatureAlgorithmByOid(string oid)
		{
			foreach (CipherSuitePlugin plugin in _plugins) {
				string[] supported = plugin.SupportedSignatureAlgorithms;
				foreach (string sig in supported) {
					SignatureAlgorithm sigAlg = plugin.GetSignatureAlgorithm(sig);
					if (oid.Equals(sigAlg.CertificateKeyAlgorithm)) {
						return sigAlg;
					}
				}
			}
			return null;
		}

		public CipherSuite GetCipherSuite(ProtocolVersion version, UInt16 id)
		{
			CipherSuiteInfo cipherSuiteInfo = null;
			foreach (CipherSuitePlugin plugin in _plugins) {
				List<UInt16> supported = new List<UInt16>(plugin.SupportedCipherSuites);
				if (supported.Contains(id)) {
					cipherSuiteInfo = plugin.GetCipherSuiteFromID(id);
					break;
				}
			}

			if (cipherSuiteInfo == null) {
				Console.WriteLine("CipherSuite ID 0x" + id.ToString("x").PadLeft(2, '0') + " not found");
				return null;
			}

			CipherSuite cipherSuite = new CipherSuite(version, id, cipherSuiteInfo.CipherSuiteName);
			if (cipherSuiteInfo.KeyExchangeAlgorithmName == null)
				cipherSuite.KeyExchangeAlgorithm = new KeyExchangeAlgorithmNull();
			if (cipherSuiteInfo.SignatureAlgorithmName == null)
				cipherSuite.SignatureAlgorithm = new SignatureAlgorithmNull();
			if (cipherSuiteInfo.BulkCipherAlgorithmName == null)
				cipherSuite.BulkCipherAlgorithm = new BulkCipherAlgorithmNull();
			if (cipherSuiteInfo.MACAlgorithmName == null)
				cipherSuite.MACAlgorithm = new MACAlgorithmNull();

			// These need to be edited in different versions
			string prfName = cipherSuiteInfo.PseudoRandomFunctionName;
			string macName = cipherSuiteInfo.MACAlgorithmName;
			
			if (version == ProtocolVersion.SSL3_0) {
				if (prfName == null) {
					prfName = "SSLv3";
				} else {
					// PRF selection not supported, but PRF defined, ignore this suite
					return null;
				}
				
				if (macName == null) {
					macName = null;
				} else if (macName.Equals("MD5")) {
					macName = "SSLv3_MD5";
				} else if (macName.Equals("SHA1")) {
					macName = "SSLv3_SHA1";
				} else {
					// Only MD5 and SHA1 MAC accepted in SSLv3, ignore this suite
					return null;
				}
			} else {
				if (version.HasSelectablePRF) {
					if (prfName == null) {
						prfName = "TLS_SHA256";
					}
				} else {
					if (prfName == null) {
						prfName = "TLSv1";
					} else {
						// PRF selection not supported, but PRF defined, ignore this suite
						return null;
					}
				}
			}

			foreach (CipherSuitePlugin plugin in _plugins) {
				if (cipherSuite.KeyExchangeAlgorithm == null) {
					cipherSuite.KeyExchangeAlgorithm =
						plugin.GetKeyExchangeAlgorithm(cipherSuiteInfo.KeyExchangeAlgorithmName);
				}
				if (cipherSuite.SignatureAlgorithm == null) {
					cipherSuite.SignatureAlgorithm =
						plugin.GetSignatureAlgorithm(cipherSuiteInfo.SignatureAlgorithmName);
				}
				if (cipherSuite.PseudoRandomFunction == null) {
					cipherSuite.PseudoRandomFunction =
						plugin.GetPseudoRandomFunction(prfName);
					
					/* Check that the PRF is valid as per RFC 5246 section 7.4.9 */
					if (cipherSuite.PseudoRandomFunction != null && cipherSuite.PseudoRandomFunction.VerifyDataLength < 12) {
						Console.WriteLine("Invalid PseudoRandomFunction, verify data less than 12, ignored");
						cipherSuite.PseudoRandomFunction = null;
					}
				}
				if (cipherSuite.BulkCipherAlgorithm == null) {
					cipherSuite.BulkCipherAlgorithm =
						plugin.GetBulkCipherAlgorithm(cipherSuiteInfo.BulkCipherAlgorithmName);
				}
				if (cipherSuite.MACAlgorithm == null) {
					cipherSuite.MACAlgorithm =
						plugin.GetMACAlgorithm(macName);
				}
			}

			if (cipherSuite.KeyExchangeAlgorithm == null || !cipherSuite.KeyExchangeAlgorithm.SupportsProtocolVersion(version)) {
				Console.WriteLine("KeyExchangeAlgorithm '" + cipherSuiteInfo.KeyExchangeAlgorithmName + "' not found");
				return null;
			}
			if (cipherSuite.SignatureAlgorithm == null || !cipherSuite.SignatureAlgorithm.SupportsProtocolVersion(version)) {
				Console.WriteLine("SignatureAlgorithm '" + cipherSuiteInfo.SignatureAlgorithmName + "' not found");
				return null;
			}
			if (cipherSuite.PseudoRandomFunction == null|| !cipherSuite.PseudoRandomFunction.SupportsProtocolVersion(version)) {
				Console.WriteLine("PseudoRandomFunction '" + cipherSuiteInfo.PseudoRandomFunctionName + "' not found");
				return null;
			}
			if (cipherSuite.BulkCipherAlgorithm == null || !cipherSuite.BulkCipherAlgorithm.SupportsProtocolVersion(version)) {
				Console.WriteLine("BulkCipherAlgorithm '" + cipherSuiteInfo.BulkCipherAlgorithmName + "' not found");
				return null;
			}
			if (cipherSuite.MACAlgorithm == null || !cipherSuite.MACAlgorithm.SupportsProtocolVersion(version)) {
				Console.WriteLine("MACAlgorithm '" + cipherSuiteInfo.MACAlgorithmName + "' not found");
				return null;
			}

			return cipherSuite;
		}
		
		
		
		
		
		
		
		

		private CipherSuitePlugin[] FindCipherSuitePlugins(string path)
		{
			List<CipherSuitePlugin> pluginList = new List<CipherSuitePlugin>();

			foreach (string fileName in Directory.GetFiles(path)) {
				FileInfo fileInfo = new FileInfo(fileName);
				if (!fileInfo.Extension.ToLower().Equals(".dll")) {
					continue;
				}

				Assembly pluginAssembly = Assembly.LoadFrom(fileName);
				foreach (Type pluginType in pluginAssembly.GetTypes()) {
					if (!pluginType.IsPublic || pluginType.IsAbstract) continue;

					/* Check that the correct interface exists with this type */
					Type cipherSuitePluginType = typeof(CipherSuitePlugin);
					if (!pluginType.IsSubclassOf(cipherSuitePluginType)) {
						continue;
					}

					CipherSuitePlugin plugin = (CipherSuitePlugin) Activator.CreateInstance(pluginType);
					Console.WriteLine("Adding plugin: " + plugin.ToString());
					pluginList.Add(plugin);
				}
			}

			return pluginList.ToArray();
		}
	}
}
