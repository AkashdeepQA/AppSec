﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Security.Cryptography;
using System.IO;
using System.Data.SqlClient;
using Microsoft.Extensions.Configuration;

namespace AppSec
{
    class Program
    {
        static void Main(string[] args)
        {
            //Adding a new comment
            #region Encoding
            /*
            string data = "Hello, World!";
            Console.WriteLine("Original Data: " + data);

            // Convert string to bytes
            byte[] bytes = Encoding.UTF8.GetBytes(data);

            // Encode bytes to Base64
            string base64Encoded = Convert.ToBase64String(bytes);
            Console.WriteLine($"Base64 Encoded: {base64Encoded}");

            // Decode Base64 back to bytes
            byte[] base64DecodedBytes = Convert.FromBase64String(base64Encoded);

            // Convert bytes back to string
            string decodedData = Encoding.UTF8.GetString(base64DecodedBytes);
            Console.WriteLine($"Decoded Data: {decodedData}");
            */
            #endregion

            #region Serialization
            /*
            Person person = new Person { Name = "John", Age = 30 };

            // Serialize object to JSON
            string json = JsonSerializer.Serialize(person);
            Console.WriteLine($"Serialized JSON: {json}");

            // Deserialize JSON back to object
            Person deserializedPerson = JsonSerializer.Deserialize<Person>(json);
            Console.WriteLine($"Deserialized Object: {deserializedPerson.Name}, {deserializedPerson.Age}");
            */
            #endregion

            #region Encryption
            
            string dataToEncrypt = "Sensitive data to encrypt";
            Console.WriteLine("Original Data: " + dataToEncrypt);

            // Generate a new RSA key pair
            using (RSA rsa = RSA.Create())
            {
                // Convert the string to bytes
                byte[] dataBytes = Encoding.UTF8.GetBytes(dataToEncrypt);

                // Encrypt the data using the public key
                byte[] encryptedData = rsa.Encrypt(dataBytes, RSAEncryptionPadding.OaepSHA1);
                Console.WriteLine($"\n\nEncrypted Data: {Convert.ToBase64String(encryptedData)}");

                // Decrypt the data using the private key
                byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA1);
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                Console.WriteLine($"\n\nDecrypted Data: {decryptedText}");
            }

            #endregion

            #region Hashing & Salting
            /*
            string password_user1 = "mysecretpassword";
            Console.WriteLine($"Original password: {password_user1}");

            // Hashing without salting
            string hashedPasswordWithoutSalt = HashPassword(password_user1);
            Console.WriteLine("Hashed password without salt: " + hashedPasswordWithoutSalt);

            // Hashing with salting
            string salt = GenerateSalt();
            string hashedPasswordWithSalt = HashPassword(password_user1, salt);
            Console.WriteLine("Hashed password with salt: " + hashedPasswordWithSalt);

            string password_user2 = "mysecretpassword";
            Console.WriteLine($"\n\nOriginal password: {password_user2}");

            // Hashing without salting - Comparision
            string hashedPasswordWithoutSalt1 = HashPassword(password_user2);
            Console.WriteLine("Hash#1 - Hashed password without salt: " + hashedPasswordWithoutSalt);
            Console.WriteLine("Hash#2 - Hashed password without salt: " + hashedPasswordWithoutSalt1);
            Console.WriteLine($"Is the Hashed string same for same values: {hashedPasswordWithoutSalt.Equals(hashedPasswordWithoutSalt1)}");
            Console.WriteLine();
            // Hashing with salting
            string salt1 = GenerateSalt();
            string hashedPasswordWithSalt1 = HashPassword(password_user2, salt);
            Console.WriteLine("Hash#1 - Hashed password with salt: " + hashedPasswordWithSalt);
            Console.WriteLine("Hash#2 - Hashed password with salt: " + hashedPasswordWithSalt1);
            Console.WriteLine($"Is the Hashed string with salt same for same values: {hashedPasswordWithSalt.Equals(hashedPasswordWithSalt1)}");
            */
            #endregion

            #region SonarCloud errors
            
            // Issue: Hardcoded password (security vulnerability)
            string password2 = "P@ssw0rd";

            // Issue: Hardcoded SQL query vulnerable to SQL Injection
            string userInput = "' OR '1'='1";  // Simulate malicious input
            string query = "SELECT * FROM Users WHERE username = '" + userInput + "'";

            // Issue: SQL connection and commands are not disposed properly (memory leak)
            SqlConnection connection = new SqlConnection("Server=myServer;Database=myDB;User Id=myUsername;Password=myPassword;");
            SqlCommand command = new SqlCommand(query, connection);
            connection.Open();
            var reader = command.ExecuteReader();

            // Issue: Use of insecure hash function (MD5 is insecure)
            System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(password2);
            byte[] hash = md5.ComputeHash(inputBytes);

            // Issue: Empty catch block (bad practice)
            try
            {
                int result = DivideNumbers(10, 0);
            }
            catch (Exception)
            {
                // Silent catch
            }

            // Issue: Hardcoded file path (security vulnerability)
            string path = "C:\\SensitiveData\\secrets.txt";

            // Issue: Potential NullReferenceException
            string nullString = null;
            Console.WriteLine(nullString.Length);

            // Issue: Insufficient randomness for cryptographic purposes (predictable output)
            Random random = new Random();
            Console.WriteLine("Weak random number: " + random.Next());

            // Issue: Unclosed FileStream causing resource leak
            FileStream fs = new FileStream(path, FileMode.Open);

            // Issue: Unused variable (code smell)
            int unusedVariable = 10;

            #endregion

            #region Secret Scanning Issues

            // Example 1: Mock AWS Credentials
            string awsAccessKey = "AKIAEXAMPLEACCESSKEY1234"; // AWS Access Key pattern
            string awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // AWS Secret Key pattern

            // Example 2: Mock GitHub Token
            string githubToken = "ghp_abcdEFGHIJKLMNOPQRSTUVWXYZ1234567890"; // GitHub token pattern

            // Example 3: Mock Slack Webhook URL
            string slackWebhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"; // Slack webhook pattern

            // Example 4: Fake Azure Storage Key
            string azureStorageKey = "sv=2019-12-12&ss=b&srt=o&sp=rw&se=2024-01-01T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=FAKEAZURESTORAGEKEY123456789"; // Azure key format

            // Example 5: Hardcoded Private Key
            string privateKey = @"
            -----BEGIN PRIVATE KEY-----
            MIIBVwIBADANBgkqhkiG9w0BAQEFAASCATwwggEoAgEAAkEAvBLA7I2aU5jFgZ3k
            YmGZp8l9Yzy/dxgMSd3GQp2dH2dMSn7z0fGsEXAMPLEoBQ==
            -----END PRIVATE KEY-----
            ";

            // Print a message for demonstration purposes
            Console.WriteLine("Potential secrets have been initialized for testing purposes!");

            #endregion

            Console.ReadLine();
            //Test2
        }

        public class Person
        {
            public string Name { get; set; }
            public int Age { get; set; }
        }

        static string GenerateSalt()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] saltBytes = new byte[16];
                rng.GetBytes(saltBytes);
                return Convert.ToBase64String(saltBytes);
            }
        }

        static
     string HashPassword(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] saltedPassword = Encoding.UTF8.GetBytes(password + salt);
                byte[] hashedBytes = sha256.ComputeHash(saltedPassword);
                return Convert.ToBase64String(hashedBytes);
            }
        }

        static string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] hashedBytes = sha256.ComputeHash(passwordBytes);
                return Convert.ToBase64String(hashedBytes);
            }
        }

        static int DivideNumbers(int a, int b)
        {
            // Issue: Division by zero (bug)
            return a / b;
        }

        static void UnusedMethod()
        {
            // This method is never called
        }

    }
}
