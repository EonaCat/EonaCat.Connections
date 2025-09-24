using EonaCat.Json;
using System.Net;

namespace EonaCat.Connections.Plugins.Client
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class ClientHttpMetricsPlugin : IClientPlugin
    {
        public string Name => "ClientMetricsPlugin";

        private NetworkClient _client;
        private long _bytesSent;
        private long _bytesReceived;
        private long _messagesSent;
        private long _messagesReceived;

        private readonly int _httpPort;
        private HttpListener _httpListener;
        private CancellationTokenSource _cts;

        public ClientHttpMetricsPlugin(int httpPort = 8080)
        {
            _httpPort = httpPort;
        }

        public void OnClientStarted(NetworkClient client)
        {
            _client = client;
            _cts = new CancellationTokenSource();
            StartHttpServer(_cts.Token);
        }

        public void OnClientConnected(NetworkClient client)
        {
            Console.WriteLine($"[{Name}] Connected to server at {client.IpAddress}:{client.Port}");
        }

        public void OnClientDisconnected(NetworkClient client, DisconnectReason reason, Exception exception)
        {
            Console.WriteLine($"[{Name}] Disconnected: {reason} {exception?.Message}");
        }

        public void OnDataReceived(NetworkClient client, byte[] data, string stringData, bool isBinary)
        {
            _bytesReceived += data.Length;
            _messagesReceived++;
        }

        public void OnError(NetworkClient client, Exception exception, string message)
        {
            Console.WriteLine($"[{Name}] Error: {message} - {exception?.Message}");
        }

        public void OnClientStopped(NetworkClient client)
        {
            _cts.Cancel();
            _httpListener?.Stop();
            Console.WriteLine($"[{Name}] Plugin stopped.");
        }

        public void IncrementSent(byte[] data)
        {
            _bytesSent += data.Length;
            _messagesSent++;
        }

        private void StartHttpServer(CancellationToken token)
        {
            _httpListener = new HttpListener();
            _httpListener.Prefixes.Add($"http://*:{_httpPort}/metrics/");
            _httpListener.Start();

            Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        var context = await _httpListener.GetContextAsync();
                        var response = context.Response;

                        var metrics = new
                        {
                            IsConnected = _client.IsConnected,
                            Ip = _client.IpAddress,
                            Port = _client.Port,
                            Uptime = _client.Uptime.TotalSeconds,
                            BytesSent = _bytesSent,
                            BytesReceived = _bytesReceived,
                            MessagesSent = _messagesSent,
                            MessagesReceived = _messagesReceived
                        };

                        var json = JsonHelper.ToJson(metrics, Formatting.Indented);
                        var buffer = System.Text.Encoding.UTF8.GetBytes(json);

                        response.ContentType = "application/json";
                        response.ContentLength64 = buffer.Length;
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length, token);
                        response.Close();
                    }
                    catch (Exception)
                    {
                        // ignore
                    }
                }
            }, token);
        }
    }
}
