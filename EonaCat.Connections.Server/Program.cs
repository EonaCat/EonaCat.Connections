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
                UseSsl = false,
                UseAesEncryption = true,
                MaxConnections = 100000,
                AesPassword = "EonaCat.Connections.Password",
                //Certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2("server.pfx", "p@ss")
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