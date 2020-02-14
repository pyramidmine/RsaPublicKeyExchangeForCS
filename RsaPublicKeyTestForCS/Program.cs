using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RsaPublicKeyTestForCS
{
	class Program
	{
		static readonly string SAMPLE_TEXT = "O2OSYS";
		static readonly byte[] SAMPLE_DATA = Encoding.UTF8.GetBytes(SAMPLE_TEXT);
		static readonly int RSA_KEY_BIT_SIZE = 2048;

		static void Main(string[] args)
		{
			//
			// 키 로드 또는 생성
			//
			byte[] privateKeyData = null;
			byte[] publicKeyData = null;
			string privateKeyFile = Path.Combine(GetKeyDirectory(), "cs.rsa.private.key");
			string publicKeyFile = Path.Combine(GetKeyDirectory(), "cs.rsa.public.key");
			if (File.Exists(privateKeyFile) && File.Exists(publicKeyFile))
			{
				// 키 파일이 있으면 로드
				privateKeyData = Convert.FromBase64String(File.ReadAllText(privateKeyFile));
				publicKeyData = Convert.FromBase64String(File.ReadAllText(publicKeyFile));
			}
			else
			{
				//
				// 키 파일이 없으면 생성
				//
				var keyGen = new RsaKeyPairGenerator();
				keyGen.Init(new KeyGenerationParameters(new SecureRandom(), RSA_KEY_BIT_SIZE));
				var keyPair = keyGen.GenerateKeyPair();

				// 개인키 데이터 저장
				var privateKeyParam = keyPair.Private as RsaKeyParameters;
				var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
				privateKeyData = privateKeyInfo.GetDerEncoded();
				File.WriteAllText(privateKeyFile, Convert.ToBase64String(privateKeyData));

				// 공개키 데이터 저장
				var publicKeyParam = keyPair.Public as RsaKeyParameters;
				var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKeyParam);
				publicKeyData = publicKeyInfo.GetDerEncoded();
				File.WriteAllText(publicKeyFile, Convert.ToBase64String(publicKeyData));
			}

			//
			// 공개키로 암호화
			//
			byte[] encryptedData = Encrypt(SAMPLE_DATA, publicKeyData);
			string encryptedFile = Path.Combine(GetKeyDirectory(), "cs.rsa.data");
			File.WriteAllText(encryptedFile, Convert.ToBase64String(encryptedData));

			//
			// 개인키로 복호화
			//
			byte[] decryptedData = Decrypt(encryptedData, privateKeyData);

			//
			// 결과 (암/복호화)
			//
			Console.WriteLine($"---------- RSA, Key: C#, Apply: C# ----------");
			Console.WriteLine($"Original Data: {Convert.ToBase64String(SAMPLE_DATA)}");
			Console.WriteLine($"Original Data: {Convert.ToBase64String(decryptedData)}");

			//
			// Signing
			//
			Console.WriteLine($"---------- RSA Signing/Verification, Key: C#, Apply: C# ----------");
			var hasher = HashAlgorithm.Create("SHA384");
			byte[] signature = CreatePrivateRSA(privateKeyData).SignData(SAMPLE_DATA, hasher);
			Console.WriteLine($"Signature Size: {signature.Length}");

			//
			// Verification
			//
			bool verified = CreatePublicRSA(publicKeyData).VerifyData(SAMPLE_DATA, hasher, signature);

			//
			// 결과 (Signing/Verification)
			//
			Console.WriteLine($"Original Data Verification: {verified}");

			// 데이터를 살짝 변경
			byte[] fakeSampleData = new byte[SAMPLE_DATA.Length];
			Array.Copy(SAMPLE_DATA, 0, fakeSampleData, 0, fakeSampleData.Length);
			fakeSampleData[5] += 1;

			//
			// Verification one more time
			// 
			verified = CreatePublicRSA(publicKeyData).VerifyData(fakeSampleData, hasher, signature);
			Console.WriteLine($"---------- RSA Signing/Verification, Key: C#, Apply: C# ----------");
			Console.WriteLine($"Fake Data Verification: {verified}");

			// 자바에서 만든 암호화 파일이 있으면 테스트
			/*
			string javaEncryptedFile = Path.Combine(GetKeyDirectory(), "cs.rsa.data.java");
			if (File.Exists(javaEncryptedFile))
			{
				byte[] encryptedData = Convert.FromBase64String(File.ReadAllText(javaEncryptedFile));

				var decryptor = new RSACryptoServiceProvider();
				decryptor.ImportCspBlob(privateKeyData);
				byte[] decryptedData = decryptor.Decrypt(encryptedData, false);

				Console.WriteLine($"---------- Key: C#, Encryption: Java ----------");
				Console.WriteLine($"Original Data: {Convert.ToBase64String(SAMPLE_DATA)}");
				Console.WriteLine($"Original Data: {Convert.ToBase64String(decryptedData)}");
			}
			*/
		}

		private static byte[] Encrypt(byte[] data, byte[] publicKeyData)
		{
			return CreatePublicRSA(publicKeyData).Encrypt(data, false);
		}

		private static byte[] Decrypt(byte[] data, byte[] privateKeyData)
		{
			return CreatePrivateRSA(privateKeyData).Decrypt(data, false);
		}

		private static RSACryptoServiceProvider CreatePublicRSA(byte[] publicKeyData)
		{
			var bcPublicKeyParam = PublicKeyFactory.CreateKey(publicKeyData) as RsaKeyParameters;
			var rsaPublicKeyParam = DotNetUtilities.ToRSAParameters(bcPublicKeyParam);
			var rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(rsaPublicKeyParam);
			return rsa;
		}

		private static RSACryptoServiceProvider CreatePrivateRSA(byte[] privateKeyData)
		{
			var bcPrivateKeyParam = PrivateKeyFactory.CreateKey(privateKeyData) as RsaPrivateCrtKeyParameters;
			var rsaPrivateKeyParam = DotNetUtilities.ToRSAParameters(bcPrivateKeyParam);
			var rsa = new RSACryptoServiceProvider();
			rsa.ImportParameters(rsaPrivateKeyParam);
			return rsa;
		}

		private static string GetKeyDirectory()
		{
			return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
		}

	}
}
