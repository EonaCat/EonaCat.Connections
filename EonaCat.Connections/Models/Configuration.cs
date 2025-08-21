using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace EonaCat.Connections.Models
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class Configuration
    {
        public bool EnableAutoReconnect { get; set; } = true;
        public int ReconnectDelayMs { get; set; } = 5000;
        public int MaxReconnectAttempts { get; set; } = 0; // 0 means unlimited attempts

        public ProtocolType Protocol { get; set; } = ProtocolType.TCP;
        public int Port { get; set; } = 8080;
        public string Host { get; set; } = "127.0.0.1";
        public bool UseSsl { get; set; } = false;
        public X509Certificate2 Certificate { get; set; }
        public bool UseAesEncryption { get; set; } = false;
        public int BufferSize { get; set; } = 8192;
        public int MaxConnections { get; set; } = 100000;
        public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);
        public bool EnableKeepAlive { get; set; } = true;
        public bool EnableNagle { get; set; } = false;

        // For testing purposes, allow self-signed certificates
        public bool IsSelfSignedEnabled { get; set; } = true;
        public string AesPassword { get; set; }
        public bool CheckCertificateRevocation { get; set; }
        public bool MutuallyAuthenticate { get; set; } = true;

        internal RemoteCertificateValidationCallback GetRemoteCertificateValidationCallback()
        {
            return CertificateValidation;
        }

        private bool CertificateValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var sw = Stopwatch.StartNew();

            try
            {
                if (IsSelfSignedEnabled)
                {
                    return true;
                }

                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    return true;
                }

                if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) && chain != null)
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        if (status.Status == X509ChainStatusFlags.RevocationStatusUnknown ||
                            status.Status == X509ChainStatusFlags.OfflineRevocation)
                        {
                            continue;
                        }

                        if (status.Status == X509ChainStatusFlags.Revoked)
                        {
                            return false;
                        }

                        return false;
                    }
                    return true;
                }
                return false;
            }
            finally
            {
                sw.Stop();
            }
        }
    }
}