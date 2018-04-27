namespace JWT.Algorithms
{
    using System;
    using System.Security.Cryptography.X509Certificates;

    public class ESAlgorithmFactory : IAlgorithmFactory
    {
        private readonly Func<X509Certificate2> _certFactory;

        public ESAlgorithmFactory(Func<X509Certificate2> certFactory)
        {
            _certFactory = certFactory;
        }

        public IJwtAlgorithm Create(string algorithmName)
        {
            return Create((JwtHashAlgorithm)Enum.Parse(typeof(JwtHashAlgorithm), algorithmName));
        }

        public IJwtAlgorithm Create(JwtHashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case JwtHashAlgorithm.ES256:
                    return new CertES256Algorithm(_certFactory());
            }

            return null;
        }
    }
}