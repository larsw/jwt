namespace JWT.Algorithms
{
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public class CertES256Algorithm : IJwtAlgorithm
    {
        private readonly X509Certificate2 _certificate;

        public CertES256Algorithm(X509Certificate2 certificate)
        {
            _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            if (_certificate.HasPrivateKey == false) throw new InvalidOperationException("The certificate has no private key associated.");
            using (var ecdsa = _certificate.GetECDsaPrivateKey())
            {
                return ecdsa.SignData(bytesToSign, HashAlgorithmName.SHA256);
            }
        }

        public bool Verify(byte[] bytesToVerify, byte[] signature)
        {
            using (var ecdsa = _certificate.GetECDsaPublicKey())
            {
                return ecdsa.VerifyData(bytesToVerify, signature, HashAlgorithmName.SHA256);
            }
        }

        public string Name => JwtHashAlgorithm.ES256.ToString();

        public bool IsAsymmetric => true;
    }
}