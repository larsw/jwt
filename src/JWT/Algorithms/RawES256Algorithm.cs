namespace JWT.Algorithms
{
    using System;
    using System.Security.Cryptography;

    public class RawES256Algorithm : IJwtAlgorithm
    {
        private readonly CngKey _key;

        public RawES256Algorithm(CngKey key)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            
            using (var ecdsa = new ECDsaCng(_key))
            {
                return ecdsa.SignData(bytesToSign, HashAlgorithmName.SHA256);
            }
        }

        public bool Verify(byte[] bytesToVerify, byte[] signature)
        {
            using (var ecdsa = new ECDsaCng(_key))
            {
                return ecdsa.VerifyData(bytesToVerify, signature, HashAlgorithmName.SHA256);
            }
        }

        public string Name => JwtHashAlgorithm.ES256.ToString();

        public bool IsAsymmetric => true;
    }
}