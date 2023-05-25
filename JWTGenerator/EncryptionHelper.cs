using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Jose;
using Newtonsoft.Json;

namespace JWTGenerator
{
    //public static class EncryptionHelper
    internal class EncryptionHelper
    {
        /// <summary>
        /// https://github.com/jwt-dotnet/jwt  
        /// </summary>
        /// <param name="jsonData">Raw data for encryption</param>
        /// <param name="sharedSecret">EncryptionSharedSecret VISA</param>
        /// <param name="apiKey">EncryptionApiKey VISA</param>
        /// <returns></returns>
        public static string JwtTokenEncryption(string jsonData, string sharedSecret, string apiKey)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                var utc0 = new DateTime(1970, 1, 1, 3, 0, 0, 0, DateTimeKind.Utc);
                var iat = (int)DateTime.Now.Subtract(utc0).TotalSeconds;

                var digest = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(sharedSecret));

                var extraHeaders = new Dictionary<string, object>
                {
                    {"kid",  apiKey},
                    {"typ", "JOSE"},
                    {"channelSecurityContext", "SHARED_SECRET"},
                    {"iat", iat},
                };

                string result = Jose.JWT.Encode(jsonData, digest, JweAlgorithm.A256GCMKW, JweEncryption.A256GCM, extraHeaders: extraHeaders);

                return result;
            }
        }

        /// <summary>
        /// https://github.com/jwt-dotnet/jwt  
        /// </summary>
        /// <param name="token">Token from VISA</param>
        /// <param name="sharedSecret">EncryptionSharedSecret VISA</param>
        /// <returns></returns>
        public static string JwtTokenDecryption(string token, string sharedSecret)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                var digest = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(sharedSecret));

                string result = Jose.JWT.Decode(token, digest, JweAlgorithm.A256GCMKW, JweEncryption.A256GCM);

                return result;
            }
        }

        public static string getXPayToken(string secret, string resourcePath, string queryString, string requestBody = "")
        {
            string timestamp = getTimestamp();
            string sourceString = timestamp + resourcePath + queryString + requestBody;
            string hash = getHash(sourceString, secret);
            string token = "xv2:" + timestamp + ":" + hash;

            return token;
        }

        private static string getTimestamp()
        {
            long timeStamp = ((long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds) / 1000;

            return timeStamp.ToString();
        }

        private static string getHash(string data, string secret)
        {
            var hashString = new HMACSHA256(Encoding.ASCII.GetBytes(secret));
            var hashBytes = hashString.ComputeHash(Encoding.ASCII.GetBytes(data));
            string digest = String.Empty;

            foreach (byte b in hashBytes)
            {
                digest += b.ToString("x2");
            }

            return digest;
        }
    }
}