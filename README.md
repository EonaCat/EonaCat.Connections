
# EonaCat.Connections
.NET Framework 4.8+ / .NET (Core) compatible library providing high-throughput TCP/UDP
servers and clients with optional TLS (for TCP) and optional application-layer encryption (TCP/UDP).

## Design goals:
 - High performance and low latency
 - Scalable to tens of thousands of concurrent connections
 - Scalable socket I/O via SocketAsyncEventArgs (SAEA) for raw TCP and UDP
 - TLS (SSL) over TCP using SslStream (built-in)
 - Optional encryption (AES-CBC + PBKDF2_SHA256) for TCP/UDP payloads
 - Minimal allocations, event-driven callbacks

#### - For highest throughput, run x64, enable LargePage, set appropriate Socket options and OS registry tuning.

## Generate self-signed certificate for TLS (TCP):
### Run as Administrator
	$cert = New-SelfSignedCertificate `
	    -DnsName "localhost" `
	    -CertStoreLocation "Cert:\LocalMachine\My" `
	    -KeyExportPolicy Exportable `
	    -NotAfter (Get-Date).AddYears(5) `
	    -FriendlyName "EonaCat Connections Test Certificate"

    $password = ConvertTo-SecureString -String "p@ss" -Force -AsPlainText

    Export-PfxCertificate `
        -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
        -FilePath "C:\temp\server.pfx" `
        -Password $password
        
#### This will create a self-signed certificate with the password 'p@ss' in the folder C:\temp\server.pfx.


## Server example:

    using EonaCat.Connections.Models;

    namespace EonaCat.Connections.Server.Example
    {
        // This file is part of the EonaCat project(s) which is released under the Apache License.
        // See the LICENSE file or go to https://EonaCat.com/license for full license details.

        public class Program
        {
            private static NetworkServer _server;

            public static void Main(string[] args)
            {
                CreateServerAsync().ConfigureAwait(false);

                while (true)
                {
                    Console.Write("Enter message to send (or 'exit' to quit): ");
                    var message = Console.ReadLine();
                    if (!string.IsNullOrEmpty(message) && message.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    {
                        _server.Stop();
                        _server.Dispose();
                        Console.WriteLine("Server stopped.");
                        break;
                    }

                    if (!string.IsNullOrEmpty(message))
                    {
                        _server.BroadcastAsync(message).ConfigureAwait(false);
                    }
                }
            }

            private static async Task CreateServerAsync()
            {
                var config = new Configuration
                {
                    Protocol = ProtocolType.TCP,
                    Port = 1111,
                    UseSsl = true,
                    UseAesEncryption = true,
                    MaxConnections = 100000,
                    AesPassword = "EonaCat.Connections.Password",
                    Certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2("server.pfx", "p@ss")
                };

                _server = new NetworkServer(config);

                // Subscribe to events
                _server.OnConnected += (sender, e) =>
                    Console.WriteLine($"Client {e.ClientId} connected from {e.RemoteEndPoint}");

                _server.OnConnectedWithNickname += (sender, e) =>
                    Console.WriteLine($"Client {e.ClientId} connected with nickname: {e.Nickname}");

                _server.OnDataReceived += async (sender, e) =>
                {
                    if (e.HasNickname)
                    {
                        Console.WriteLine($"Received from {e.Nickname}: {(e.IsBinary ? $"{e.Data.Length} bytes" : e.StringData)}");
                    }
                    else
                    {
                        Console.WriteLine($"Received from {e.ClientId}: {(e.IsBinary ? $"{e.Data.Length} bytes" : e.StringData)}");
                    }                    

                    // Echo back the message
                    if (e.IsBinary)
                    {
                        await _server.SendToClientAsync(e.ClientId, e.Data);
                    }
                    else
                    {
                        await _server.SendToClientAsync(e.ClientId, $"Echo: {e.StringData}");
                    }
                };

                _server.OnDisconnected += (sender, e) =>
                {
                    if (e.HasNickname)
                    {
                        Console.WriteLine($"Client {e.Nickname} disconnected");
                    }
                    else
                    {
                        Console.WriteLine($"Client {e.ClientId} disconnected");
                    }
                };

                await _server.StartAsync();
            }
        }
    }

## Client example:

	using EonaCat.Connections.Models;

    namespace EonaCat.Connections.Client.Example
    {
        // This file is part of the EonaCat project(s) which is released under the Apache License.
        // See the LICENSE file or go to https://EonaCat.com/license for full license details.

        public class Program
        {
            private static NetworkClient _client;

            public static async Task Main(string[] args)
            {
                await CreateClientAsync().ConfigureAwait(false);

                while (true)
                {
                    if (!_client.IsConnected)
                    {
                        await Task.Delay(1000).ConfigureAwait(false);
                        continue;
                    }

                    Console.Write("Enter message to send (or 'exit' to quit): ");
                    var message = Console.ReadLine();

                    if (!string.IsNullOrEmpty(message) && message.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    {
                        await _client.DisconnectAsync().ConfigureAwait(false);
                        break;
                    }

                    if (!string.IsNullOrEmpty(message))
                    {
                        await _client.SendAsync(message).ConfigureAwait(false);
                    }
                }
            }

            private static async Task CreateClientAsync()
            {
                var config = new Configuration
                {
                    Protocol = ProtocolType.TCP,
                    Host = "127.0.0.1",
                    Port = 1111,
                    UseSsl = true,
                    UseAesEncryption = true,
                    AesPassword = "EonaCat.Connections.Password",
                    Certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2("client.pfx", "p@ss"),
                };

                _client = new NetworkClient(config);

                _client.OnGeneralError += (sender, e) =>
                    Console.WriteLine($"Error: {e.Message}");

                // Subscribe to events
                _client.OnConnected += async (sender, e) =>
                {
                    Console.WriteLine($"Connected to server at {e.RemoteEndPoint}");

                    // Set nickname
                    await _client.SetNicknameAsync("TestUser");

                    // Send a message
                    await _client.SendAsync("Hello server!");
                };

                _client.OnDataReceived += (sender, e) =>
                    Console.WriteLine($"Server says: {(e.IsBinary ? $"{e.Data.Length} bytes" : e.StringData)}");

                _client.OnDisconnected += (sender, e) =>
                {
                    Console.WriteLine("Disconnected from server");
                };

                Console.WriteLine("Connecting to server...");
                await _client.ConnectAsync();
            }
        }
    }