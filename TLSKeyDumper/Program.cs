using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;


namespace TLSKeyDumper
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: TLSKeyDumper <https-url> <output-path>");
                return;
            }

            string url = args[0];
            string outputPath = args[1];

            Uri uriResult;
            bool result = Uri.TryCreate(url, UriKind.Absolute, out uriResult) && (uriResult.Scheme == Uri.UriSchemeHttps);
            if (!result) {
                Console.WriteLine("[ERROR] Invalid URL was provided in the arguments \"{0}\"", uriResult.ToString());
            }
            
            Uri uri = new Uri(url);
            string host = uri.Host;
            int port = uri.Port == -1 ? 443 : uri.Port;

            Server_DumpTlsKeys(host, port, outputPath);
            Console.WriteLine("===========================");
            Console.WriteLine("Search for local certificate...");
            Client_DumpTlsKeys(host, port, outputPath);
        }

        static void Server_DumpTlsKeys(string host, int port, string outputPath)
        {
            using (TcpClient client = new TcpClient(host, port))
            using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(Server_ValidateServerCertificate), null))
            {
                // Perform the TLS handshake and use the server's certificate
                sslStream.AuthenticateAsClient(host);

                // Capture the server's certificate and session information
                X509Certificate serverCert = sslStream.RemoteCertificate;
                if (serverCert != null)
                {
                    Server_DumpServerCertificate(serverCert, outputPath, host);
                }
                else
                {
                    Console.WriteLine("No server certificate was found.");
                }

                // Capture the session information for Wireshark decryption
                Server_CaptureTlsSessionInformation(sslStream);

                Console.WriteLine("TLS handshake complete.");
            }
        }

        static void Server_DumpServerCertificate(X509Certificate certificate, string outputPath, string host)
        {
            string sanitizedHost = host.Replace("www.", "").Replace("www", "").Replace(".", "-");
            StringBuilder myStringBuilder = new StringBuilder("");
            myStringBuilder.AppendFormat("certificate_{0}.pem", sanitizedHost);
            string certPath = Path.Combine(outputPath, myStringBuilder.ToString());
            byte[] certBytes = certificate.Export(X509ContentType.Cert);
            File.WriteAllBytes(certPath, certBytes);
            Console.WriteLine($"Server certificate dumped to {certPath}");
        }

        static void Server_CaptureTlsSessionInformation(SslStream sslStream)
        {
            // Implement your logic to capture session information such as session keys if accessible.
            // Example: Log session details that might be useful for Wireshark
            Console.WriteLine("Cipher Algorithm: " + sslStream.CipherAlgorithm);
            Console.WriteLine("Cipher Strength: " + sslStream.CipherStrength);
            Console.WriteLine("Hash Algorithm: " + sslStream.HashAlgorithm);
            Console.WriteLine("Hash Strength: " + sslStream.HashStrength);
            Console.WriteLine("Key Exchange Algorithm: " + sslStream.KeyExchangeAlgorithm);
            Console.WriteLine("Key Exchange Strength: " + sslStream.KeyExchangeStrength);
        }

        static bool Server_ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Always accept the server certificate for debugging purposes
            
            Console.WriteLine("Validate Server Certificate: accept the server certificate for debugging purposes");
            Console.WriteLine("Key Algorithm: " + certificate.GetKeyAlgorithm());
            Console.WriteLine("Cert Hash String: " + certificate.GetCertHashString());
            Console.WriteLine("Effectiv eDate: " + certificate.GetEffectiveDateString());
            Console.WriteLine("Expiration Date: " + certificate.GetExpirationDateString());
            Console.WriteLine("Public Key: " + certificate.GetPublicKeyString());
            return true;
        }

        static void Client_DumpTlsKeys(string host, int port, string outputPath)
        {
            using (TcpClient client = new TcpClient(host, port))
            using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(Client_ValidateServerCertificate), null))
            {
                // Find a client certificate from all accessible stores
                X509Certificate2 cert = Client_FindCertificate(host);

                if (cert != null)
                {
                    sslStream.AuthenticateAsClient(host, new X509CertificateCollection(new X509Certificate[] { cert }), System.Security.Authentication.SslProtocols.Tls12, false);

                    // Dump the private key to the specified output path
                    Client_ExportPrivateKey(cert, outputPath);
                }
                else
                {
                    Console.WriteLine("No client certificate found, proceeding without it.");
                    sslStream.AuthenticateAsClient(host);
                }

                // Capture the session information for Wireshark decryption
                Client_CaptureTlsSessionInformation(sslStream);

                Console.WriteLine("TLS handshake complete.");
            }
        }

        static X509Certificate2 Client_FindCertificate(string host)
        {
            foreach (StoreLocation storeLocation in Enum.GetValues(typeof(StoreLocation)))
            {
                X509Store store = new X509Store(StoreName.My, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    if (cert.Subject.Contains(host, StringComparison.OrdinalIgnoreCase))
                    {
                        store.Close();
                        return cert;
                    }
                }
                store.Close();
            }
            return null;
        }

        static void Client_ExportPrivateKey(X509Certificate2 cert, string outputPath)
        {
            if (cert.HasPrivateKey)
            {
                RSA privateKey = cert.GetRSAPrivateKey();
                string privateKeyPem = Client_ExportPrivateKeyToPem(privateKey.ExportPkcs8PrivateKey());
                string privateKeyPath = Path.Combine(outputPath, $"private_key_{cert.Thumbprint}.pem");

                File.WriteAllText(privateKeyPath, privateKeyPem);
                Console.WriteLine($"Private key dumped to {privateKeyPath}");
            }
            else
            {
                Console.WriteLine("No private key found.");
            }
        }

        static string Client_ExportPrivateKeyToPem(byte[] privateKeyBytes)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END PRIVATE KEY-----");
            return builder.ToString();
        }

        static void Client_CaptureTlsSessionInformation(SslStream sslStream)
        {
            // Implement your logic to capture session information such as session keys if accessible.
            // Example: Log session details that might be useful for Wireshark
            Console.WriteLine("Cipher Algorithm: " + sslStream.CipherAlgorithm);
            Console.WriteLine("Cipher Strength: " + sslStream.CipherStrength);
            Console.WriteLine("Hash Algorithm: " + sslStream.HashAlgorithm);
            Console.WriteLine("Hash Strength: " + sslStream.HashStrength);
            Console.WriteLine("Key Exchange Algorithm: " + sslStream.KeyExchangeAlgorithm);
            Console.WriteLine("Key Exchange Strength: " + sslStream.KeyExchangeStrength);
        }

        static bool Client_ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Always accept the server certificate for debugging purposes
            return true;
        }
    }

}
