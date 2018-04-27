using System.Security.Cryptography;

namespace JWT.Algorithms
{
    using System;

    /// <summary>
    /// HMAC using SHA-384
    /// </summary>
    public sealed class HMACSHA384Algorithm : IJwtAlgorithm
    {
        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using (var sha = new HMACSHA384(key))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }

        public bool Verify(byte[] bytesToVerify, byte[] signature)
        {
            throw new InvalidOperationException();
        }

        /// <inheritdoc />
        public string Name => JwtHashAlgorithm.HS384.ToString();

        /// <inheritdoc />
        public bool IsAsymmetric { get; } = false;
    }
}