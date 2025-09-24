using EonaCat.Connections.Models;

namespace EonaCat.Connections.Plugins.Server
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class MetricsPlugin : IServerPlugin
    {
        public string Name => "MetricsPlugin";

        private readonly TimeSpan _interval;
        private CancellationTokenSource _cts;
        private NetworkServer _server;

        public MetricsPlugin(TimeSpan interval)
        {
            _interval = interval;
        }

        public void OnServerStarted(NetworkServer server)
        {
            _server = server;
            _cts = new CancellationTokenSource();

            Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        var stats = server.GetStats();

                        Console.WriteLine(
                            $"[{Name}] Uptime: {stats.Uptime:g} | " +
                            $"Active: {stats.ActiveConnections} | " +
                            $"Total: {stats.TotalConnections} | " +
                            $"Msgs In: {stats.MessagesReceived} | " +
                            $"Msgs Out: {stats.MessagesSent} | " +
                            $"Bytes In: {stats.BytesReceived} | " +
                            $"Bytes Out: {stats.BytesSent} | " +
                            $"Msg/s: {stats.MessagesPerSecond:F2}"
                        );

                        await Task.Delay(_interval, _cts.Token);
                    }
                    catch (TaskCanceledException) { }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[{Name}] Error logging metrics: {ex}");
                    }
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
