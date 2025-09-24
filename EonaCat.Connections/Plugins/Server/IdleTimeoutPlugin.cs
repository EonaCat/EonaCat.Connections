using EonaCat.Connections.Models;

namespace EonaCat.Connections.Plugins.Server
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class IdleTimeoutPlugin : IServerPlugin
    {
        public string Name => "IdleTimeoutPlugin";

        private readonly TimeSpan _timeout;
        private CancellationTokenSource _cts;

        public IdleTimeoutPlugin(TimeSpan timeout)
        {
            _timeout = timeout;
        }

        public void OnServerStarted(NetworkServer server)
        {
            _cts = new CancellationTokenSource();

            // Background task to check idle clients
            Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    foreach (var kvp in server.GetClients())
                    {
                        var client = kvp.Value;
                        if (DateTime.UtcNow - client.LastActive > _timeout)
                        {
                            Console.WriteLine($"[{Name}] Disconnecting idle client {client.RemoteEndPoint}");
                            _ = server.DisconnectClientAsync(client.Id, DisconnectReason.Timeout);
                        }
                    }

                    await Task.Delay(5000, _cts.Token); // Check every 5s
                }
            }, _cts.Token);
        }

        public void OnServerStopped(NetworkServer server)
        {
            _cts?.Cancel();
        }

        public void OnClientConnected(Connection client) { }
        public void OnClientDisconnected(Connection client, DisconnectReason reason, Exception exception) { }
        public void OnDataReceived(Connection client, byte[] data, string stringData, bool isBinary) { }
    }
}
