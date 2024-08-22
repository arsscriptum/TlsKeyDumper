## TLSKeyDumper Application

`TLSKeyDumper` is a command line application to help retrieve informations about TLS connections. The end goal is to provide the data required to decrypt and analyse TLS network traffic in WireShark.

`TLSKeyDumper` is searching for a client certificate in your local certificate store that matches the domain name (e.g., `www.microsoft.com`). However, you probably don’t have a client certificate for the domain you are trying to connect to, most do not require client certificate authentications.

The application expects two command-line arguments

1. The HTTPS URL to connect to.
2. The output directory path where the private key file should be saved.

### Usage Example
   - When running the application, you would now specify the URL and the directory where you want the private key to be saved.
```bash
   TLSKeyDumper\bin\Debug\netcoreapp3.1\TLSKeyDumper.exe https://www.example.com C:\path\to\output\directory
```

The private key file is named based on the certificate’s thumbprint and saved to the directory specified in the command-line argument.

### **Security Considerations:**
- **Ensure the output directory is secure** and has restricted access to avoid unauthorized access to the private key files.
- **Clean up** private key files after use to prevent security risks.


### **Understanding Client Certificates:**

1. **Client Certificates vs. Server Certificates:**
   - **Server Certificates:** When you connect to `https://www.microsoft.com` (or any HTTPS site) using your browser, the server presents its certificate to your browser. Your browser verifies this certificate to ensure that the server is who it claims to be. This is standard HTTPS behavior.
   - **Client Certificates:** These are used when a server requires the client (you) to present a certificate for authentication. This is not typical for most public websites. Client certificates are more common in environments where mutual TLS (mTLS) is required, such as corporate intranets, VPNs, or secure API services.

2. **Browser Connections:**
   - When you connect to `https://www.microsoft.com` using a browser, the browser does not use a client certificate. Instead, it simply trusts the server’s certificate after verifying it against a trusted certificate authority (CA).

3. **TLSKeyDumper's Search for Client Certificates:**
   - `TLSKeyDumper` is searching for a client certificate in your local certificate store that matches the domain name (e.g., `www.microsoft.com`). However, you probably don’t have a client certificate for this domain because `www.microsoft.com` does not require client certificate authentication. 

### **Why No Client Certificate is Found:**
- **No Requirement for Client Certificate:** The connection to `https://www.microsoft.com` doesn’t require a client certificate. This is why the application doesn’t find one, but your browser still connects successfully.
- **Typical Scenario:** Most public websites, including Microsoft’s, do not require clients (browsers) to present a certificate. They only need to verify the server’s certificate.

If your goal is to connect to `https://www.microsoft.com` and potentially log TLS session details for decryption in Wireshark, you don’t need a client certificate. You should modify the `TLSKeyDumper` to proceed without looking for a client certificate and focus on capturing the server's certificate and session details.



## Use SSL Key Logging for Wireshark
   - Instead of focusing on client certificates, focus on logging the SSL/TLS session keys using the `SSLKEYLOGFILE` environment variable as mentioned earlier.
   - This allows you to capture and decrypt the TLS traffic using Wireshark without needing to export private keys or rely on client certificates.

### **Summary:**
The reason no client certificate is found is that `https://www.microsoft.com` doesn’t require one. Your browser connects by verifying the server’s certificate, not by presenting a client certificate. Modify `TLSKeyDumper` to proceed without a client certificate and use SSL key logging to capture the necessary details for decrypting the traffic in Wireshark.

## Troubleshooting 

If setting the `SSLKEYLOGFILE` environment variable doesn't result in a file being generated, there could be several reasons for this. Here are some steps to troubleshoot and ensure the SSL key logging is working as expected:

### **1. Check .NET Version**
The `SSLKEYLOGFILE` environment variable is supported in .NET Core 3.1 and later versions. Ensure that your application is targeting a compatible .NET version.

### **2. Ensure the Environment Variable is Set Correctly**
Make sure the `SSLKEYLOGFILE` environment variable is set in the environment where the application is running. You can set it directly in the PowerShell or Command Prompt before running your application:

**PowerShell:**
```powershell
$env:SSLKEYLOGFILE = "D:\path\to\output\directory\sslkeys.log"
```

**Command Prompt:**
```cmd
set SSLKEYLOGFILE=D:\path\to\output\directory\sslkeys.log
```

### **3. Verify Write Permissions**
Ensure that the directory specified in the `SSLKEYLOGFILE` path has write permissions for the user running the application. If the application doesn't have permission to write to the file, the file won't be created.

### **4. Use Full Path**
Make sure you are using the full path for the `SSLKEYLOGFILE` variable. Relative paths might cause issues.

### **5. Run the Application**
After setting the environment variable, run your application. Make sure you're running it in the same environment where `SSLKEYLOGFILE` is set:

```bash
dotnet run https://www.microsoft.com D:\path\to\output\directory
```

### **6. Check if the Application is Using Sockets Directly**
If your application uses libraries or methods that do not rely on the standard .NET HTTP stack, such as directly using `TcpClient` and `SslStream`, the `SSLKEYLOGFILE` might not work as expected. The key logging primarily works with the standard `HttpClient` or `WebRequest` implementations.


### **9. Alternative Approach**
If `SSLKEYLOGFILE` continues to fail, consider using a proxy tool like [Fiddler](https://www.telerik.com/fiddler) or [Burp Suite](https://portswigger.net/burp) that can capture and decrypt HTTPS traffic directly, without needing to modify your application.

### **Summary**
The `SSLKEYLOGFILE` should work in supported .NET versions and environments. Ensure the variable is correctly set, that you have write permissions, and that the application is utilizing the standard HTTP stack. If issues persist, testing with a simple `HttpClient` application can help verify the functionality.