path %path%;C:\Windows\Microsoft.NET\Framework\v4.0.30319
mkdir build

:: Compile the base AaltoTLS libraries
csc /out:build\AaltoTLS.PluginInterface.dll /r:System.dll /t:library AaltoTLS.PluginInterface\*.cs AaltoTLS.PluginInterface\CipherSuitePluginInterface\*.cs
csc /out:build\AaltoTls.dll /r:System.dll /r:build\AaltoTLS.PluginInterface.dll /t:library AaltoTLS\*.cs AaltoTLS\Protocol\*.cs

:: Compile all the plugin files
csc /out:build\BaseCipherSuitePlugin.dll /r:System.dll /r:build\AaltoTLS.PluginInterface.dll /t:library Plugins\BaseCipherSuitePlugin\*.cs
csc /out:build\ARCFourCipherSuitePlugin.dll /r:System.dll /r:build\AaltoTLS.PluginInterface.dll /t:library Plugins\ARCFourCipherSuitePlugin\*.cs
csc /out:build\CamelliaCipherSuitePlugin.dll /r:System.dll /r:build\AaltoTLS.PluginInterface.dll /t:library Plugins\CamelliaCipherSuitePlugin\*.cs
csc /out:build\EllipticCurveCipherSuitePlugin.dll /r:System.dll /r:System.Core.dll /r:build\AaltoTLS.PluginInterface.dll /t:library Plugins\EllipticCurveCipherSuitePlugin\*.cs

::csc /out:build\BigIntegerCipherSuitePlugin.dll /unsafe /r:System.dll /r:build\AaltoTLS.PluginInterface.dll /t:library Plugins\BigIntegerCipherSuitePlugin\*.cs Plugins\BigIntegerCipherSuitePlugin\Mono.Math\BigInteger\*.cs Plugins\BigIntegerCipherSuitePlugin\Mono.Math\Prime\*.cs Plugins\BigIntegerCipherSuitePlugin\Mono.Math\Prime.Generator\*.cs
csc /out:build\BigIntegerCipherSuitePlugin.dll /d:NET_4_0 /r:System.dll /r:System.Numerics.dll /r:build\AaltoTLS.PluginInterface.dll /t:library Plugins\BigIntegerCipherSuitePlugin\BigIntegerCipherSuitePlugin.cs Plugins\BigIntegerCipherSuitePlugin\KeyExchangeAlgorithmDHE.cs Plugins\BigIntegerCipherSuitePlugin\SignatureAlgorithmRSA.cs

:: Compile the sample code
csc /out:build\TLSClient.exe /r:System.dll /r:build\AaltoTLS.PluginInterface.dll /r:build\AaltoTLS.dll /t:exe Samples\TLSClient\TLSClient.cs
csc /out:build\TLSServer.exe /r:System.dll /r:build\AaltoTLS.PluginInterface.dll /r:build\AaltoTLS.dll /t:exe Samples\TLSServer\TLSServer.cs
