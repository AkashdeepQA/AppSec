using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.Security.Cryptography;
using System.IO;
using System.Data.SqlClient;

namespace AppSec
{
    class Program
    {
        static void Main(string[] args)
        {
            #region Encoding

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

            #endregion

            #region Serialization

            Person person = new Person { Name = "John", Age = 30 };

            // Serialize object to JSON
            string json = JsonSerializer.Serialize(person);
            Console.WriteLine($"Serialized JSON: {json}");

            // Deserialize JSON back to object
            Person deserializedPerson = JsonSerializer.Deserialize<Person>(json);
            Console.WriteLine($"Deserialized Object: {deserializedPerson.Name}, {deserializedPerson.Age}");

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

            string password = "mysecretpassword";
            Console.WriteLine($"Original password: {password}");

            // Hashing without salting
            string hashedPasswordWithoutSalt = HashPassword(password);
            Console.WriteLine("Hashed password without salt: " + hashedPasswordWithoutSalt);

            // Hashing with salting
            string salt = GenerateSalt();
            string hashedPasswordWithSalt = HashPassword(password, salt);
            Console.WriteLine("Hashed password with salt: " + hashedPasswordWithSalt);

            #endregion

            #region SonanrCloud errors

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
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(password);
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

            Console.ReadLine();
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
