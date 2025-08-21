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
                UseSsl = false,
                UseAesEncryption = true,
                AesPassword = "EonaCat.Connections.Password",
                //Certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2("client.pfx", "p@ss"),
            };

            _client = new NetworkClient(config);

            // Subscribe to events
            _client.OnConnected += (sender, e) =>
            {
                Console.WriteLine($"Connected to server at {e.RemoteEndPoint}");
            };

            _client.OnDataReceived += (sender, e) =>
                Console.WriteLine($"Server says: {(e.IsBinary ? $"{e.Data.Length} bytes" : e.StringData)}");

            _client.OnDisconnected += (sender, e) =>
            {
                Console.WriteLine("Disconnected from server");
            };

            await _client.ConnectAsync();

            // Send nickname
            await _client.SendNicknameAsync("TestUser");

            // Send a message
            await _client.SendAsync("Hello server!");
        }
    }
}