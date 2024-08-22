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

            Uri uri = new Uri(url);
            string host = uri.Host;
            int port = uri.Port == -1 ? 443 : uri.Port;

            DumpTlsKeys(host, port, outputPath);
        }

        static void DumpTlsKeys(string host, int port, string outputPath)
        {
            using (TcpClient client = new TcpClient(host, port))
            using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null))
            {
                // Perform the TLS handshake and use the server's certificate
                sslStream.AuthenticateAsClient(host);

                // Capture the server's certificate and session information
                X509Certificate serverCert = sslStream.RemoteCertificate;
                if (serverCert != null)
                {
                    DumpServerCertificate(serverCert, outputPath);
                }
                else
                {
                    Console.WriteLine("No server certificate was found.");
                }

                // Capture the session information for Wireshark decryption
                CaptureTlsSessionInformation(sslStream);

                Console.WriteLine("TLS handshake complete.");
            }
        }

        static void DumpServerCertificate(X509Certificate certificate, string outputPath)
        {
            string certPath = Path.Combine(outputPath, "server_certificate.pem");
            byte[] certBytes = certificate.Export(X509ContentType.Cert);
            File.WriteAllBytes(certPath, certBytes);
            Console.WriteLine($"Server certificate dumped to {certPath}");
        }

        static void CaptureTlsSessionInformation(SslStream sslStream)
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

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Always accept the server certificate for debugging purposes
            return true;
        }
    }
}

/*
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

            Uri uri = new Uri(url);
            string host = uri.Host;
            int port = uri.Port == -1 ? 443 : uri.Port;

            DumpTlsKeys(host, port, outputPath);
        }

        static void DumpTlsKeys(string host, int port, string outputPath)
        {
            using (TcpClient client = new TcpClient(host, port))
            using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null))
            {
                // Find a client certificate from all accessible stores
                X509Certificate2 cert = FindCertificate(host);

                if (cert != null)
                {
                    sslStream.AuthenticateAsClient(host, new X509CertificateCollection(new X509Certificate[] { cert }), System.Security.Authentication.SslProtocols.Tls12, false);

                    // Dump the private key to the specified output path
                    ExportPrivateKey(cert, outputPath);
                }
                else
                {
                    Console.WriteLine("No client certificate found, proceeding without it.");
                    sslStream.AuthenticateAsClient(host);
                }

                // Capture the session information for Wireshark decryption
                CaptureTlsSessionInformation(sslStream);

                Console.WriteLine("TLS handshake complete.");
            }
        }

        static X509Certificate2 FindCertificate(string host)
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

        static void ExportPrivateKey(X509Certificate2 cert, string outputPath)
        {
            if (cert.HasPrivateKey)
            {
                RSA privateKey = cert.GetRSAPrivateKey();
                string privateKeyPem = ExportPrivateKeyToPem(privateKey.ExportPkcs8PrivateKey());
                string privateKeyPath = Path.Combine(outputPath, $"private_key_{cert.Thumbprint}.pem");

                File.WriteAllText(privateKeyPath, privateKeyPem);
                Console.WriteLine($"Private key dumped to {privateKeyPath}");
            }
            else
            {
                Console.WriteLine("No private key found.");
            }
        }

        static string ExportPrivateKeyToPem(byte[] privateKeyBytes)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END PRIVATE KEY-----");
            return builder.ToString();
        }

        static void CaptureTlsSessionInformation(SslStream sslStream)
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

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Always accept the server certificate for debugging purposes
            return true;
        }
    }
}
/*
namespace TLSKeyDumper
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: TLSKeyDumper <https-url>");
                return;
            }

            string url = args[0];
            Uri uri = new Uri(url);
            string host = uri.Host;
            int port = uri.Port == -1 ? 443 : uri.Port;

            DumpTlsKeys(host, port);
        }
      // static void DumpTlsKeys(string host, int port)
   //     {
      //      using (TcpClient client = new TcpClient(host, port))
      ////      using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null))
            {
                // Perform the TLS handshake without a client certificate
        //        sslStream.AuthenticateAsClient(host);

                // Capture session information (although without client certificate involvement)
            //    CaptureTlsSessionInformation(sslStream);

           //     Console.WriteLine("TLS handshake complete.");
          //  }
    //    }
        
        static void DumpTlsKeys(string host, int port)
        {
            using (TcpClient client = new TcpClient(host, port))
            using (SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null))
            {
                // Perform the TLS handshake without a client certificate
                sslStream.AuthenticateAsClient(host);

                // Capture session information (although without client certificate involvement)
                CaptureTlsSessionInformation(sslStream);

                Console.WriteLine("TLS handshake complete.");

                // Load the certificate from the local store
                X509Certificate2 cert = GetCertificate(host);

                if (cert == null)
                {
                    Console.WriteLine("No certificate found for the specified host.");
                    return;
                }

                // Perform the TLS handshake
                sslStream.AuthenticateAsClient(host, new X509CertificateCollection(new X509Certificate[] { cert }), System.Security.Authentication.SslProtocols.Tls12, false);

                // Dump the private key
                ExportPrivateKey(cert);

                // Optionally, capture additional information for decryption
                CaptureTlsSessionInformation(sslStream);

                Console.WriteLine("TLS handshake complete.");
            }
        }

        static X509Certificate2 GetCertificate(string host)
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, host, false);
            store.Close();

            return certs.Count > 0 ? certs[0] : null;
        }

        static void ExportPrivateKey(X509Certificate2 cert)
        {
            if (cert.HasPrivateKey)
            {
                // Export the private key to a PEM file
                RSA privateKey = cert.GetRSAPrivateKey();
                string privateKeyPem = ExportPrivateKeyToPem(privateKey);
                string privateKeyPath = $"private_key_{cert.Thumbprint}.pem";

                File.WriteAllText(privateKeyPath, privateKeyPem);
                Console.WriteLine($"Private key dumped to {privateKeyPath}");
            }
            else
            {
                Console.WriteLine("No private key found.");
            }
        }

        static string ExportPrivateKeyToPem(RSA privateKey)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(privateKey.ExportPkcs8PrivateKey(), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END PRIVATE KEY-----");
            return builder.ToString();
        }

        static void CaptureTlsSessionInformation(SslStream sslStream)
        {
            // Implement your logic to capture other necessary session information.
            // For example, you might want to log the session ID, cipher suite, etc.
            Console.WriteLine("Cipher Suite: " + sslStream.CipherAlgorithm);
            Console.WriteLine("Key Exchange Algorithm: " + sslStream.KeyExchangeAlgorithm);
            Console.WriteLine("Hash Algorithm: " + sslStream.HashAlgorithm);
        }

        static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Always accept the server certificate for debugging purposes
            return true;
        }
    }
}
*/