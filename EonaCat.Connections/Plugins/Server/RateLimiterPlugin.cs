using EonaCat.Connections.Models;
using System.Collections.Concurrent;

namespace EonaCat.Connections.Plugins.Server
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class RateLimiterPlugin : IServerPlugin
    {
        public string Name => "RateLimiterPlugin";

        private readonly int _maxMessages;
        private readonly TimeSpan _interval;
        private readonly ConcurrentDictionary<string, ConcurrentQueue<DateTime>> _messageTimestamps;

        public RateLimiterPlugin(int maxMessages, TimeSpan interval)
        {
            _maxMessages = maxMessages;
            _interval = interval;
            _messageTimestamps = new ConcurrentDictionary<string, ConcurrentQueue<DateTime>>();
        }

        public void OnServerStarted(NetworkServer server) { }
        public void OnServerStopped(NetworkServer server) { }

        public void OnClientConnected(Connection client)
        {
            _messageTimestamps[client.Id] = new ConcurrentQueue<DateTime>();
        }

        public void OnClientDisconnected(Connection client, DisconnectReason reason, Exception exception)
        {
            _messageTimestamps.TryRemove(client.Id, out _);
        }

        public void OnDataReceived(Connection client, byte[] data, string stringData, bool isBinary)
        {
            if (!_messageTimestamps.TryGetValue(client.Id, out var queue)) return;

            var now = DateTime.UtcNow;
            queue.Enqueue(now);

            // Remove old timestamps
            while (queue.TryPeek(out var oldest) && now - oldest > _interval)
                queue.TryDequeue(out _);

            if (queue.Count > _maxMessages)
            {
                Console.WriteLine($"[{Name}] Client {client.RemoteEndPoint} exceeded rate limit. Disconnecting...");
                
                // Force disconnect
                client.TcpClient?.Close();
            }
        }
    }
}
