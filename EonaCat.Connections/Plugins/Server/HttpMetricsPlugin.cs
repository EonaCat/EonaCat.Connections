using EonaCat.Connections.Models;
using EonaCat.Json;
using System.Net;
using System.Text;

namespace EonaCat.Connections.Plugins.Server
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class HttpMetricsPlugin : IServerPlugin
    {
        public string Name => "HttpMetricsPlugin";

        private readonly int _port;
        private HttpListener _httpListener;
        private CancellationTokenSource _cts;
        private NetworkServer _server;

        public HttpMetricsPlugin(int port = 9100)
        {
            _port = port;
        }

        public void OnServerStarted(NetworkServer server)
        {
            _server = server;
            _cts = new CancellationTokenSource();
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add($"http://*:{_port}/metrics/");

            try
            {
                _httpListener.Start();
                Console.WriteLine($"[{Name}] Metrics endpoint running at http://localhost:{_port}/metrics/");
            }
            catch (HttpListenerException ex)
            {
                Console.WriteLine($"[{Name}] Failed to start HTTP listener: {ex.Message}");
                return;
            }

            Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        var context = await _httpListener.GetContextAsync();

                        if (context.Request.Url.AbsolutePath == "/metrics")
                        {
                            var stats = _server.GetStats();

                            var responseObj = new
                            {
                                uptime = stats.Uptime.ToString(),
                                startTime = stats.StartTime,
                                activeConnections = stats.ActiveConnections,
                                totalConnections = stats.TotalConnections,
                                bytesSent = stats.BytesSent,
                                bytesReceived = stats.BytesReceived,
                                messagesSent = stats.MessagesSent,
                                messagesReceived = stats.MessagesReceived,
                                messagesPerSecond = stats.MessagesPerSecond
                            };

                            var json = JsonHelper.ToJson(responseObj, Formatting.Indented);
                            var buffer = Encoding.UTF8.GetBytes(json);

                            context.Response.ContentType = "application/json";
                            context.Response.StatusCode = 200;
                            await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                            context.Response.OutputStream.Close();
                        }
                        else
                        {
                            context.Response.StatusCode = 404;
                            context.Response.Close();
                        }
                    }
                    catch (ObjectDisposedException) { }
                    catch (HttpListenerException) { }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[{Name}] Error: {ex}");
                    }
                }
            }, _cts.Token);
        }

        public void OnServerStopped(NetworkServer server)
        {
            _cts?.Cancel();
            if (_httpListener != null && _httpListener.IsListening)
            {
                _httpListener.Stop();
                _httpListener.Close();
            }
        }

        public void OnClientConnected(Connection client) { }
        public void OnClientDisconnected(Connection client, DisconnectReason reason, Exception exception) { }
        public void OnDataReceived(Connection client, byte[] data, string stringData, bool isBinary) { }
    }
}
