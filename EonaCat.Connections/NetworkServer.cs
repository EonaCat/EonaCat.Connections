using EonaCat.Connections.EventArguments;
using EonaCat.Connections.Helpers;
using EonaCat.Connections.Models;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ErrorEventArgs = EonaCat.Connections.EventArguments.ErrorEventArgs;

namespace EonaCat.Connections
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class NetworkServer
    {
        private readonly Configuration _config;
        private readonly Stats _stats;
        private readonly ConcurrentDictionary<string, Connection> _clients;
        private TcpListener _tcpListener;
        private UdpClient _udpListener;
        private CancellationTokenSource _serverCancellation;
        private readonly object _statsLock = new object();

        public event EventHandler<ConnectionEventArgs> OnConnected;
        public event EventHandler<ConnectionEventArgs> OnConnectedWithNickname;
        public event EventHandler<DataReceivedEventArgs> OnDataReceived;
        public event EventHandler<ConnectionEventArgs> OnDisconnected;
        public event EventHandler<ErrorEventArgs> OnSslError;
        public event EventHandler<ErrorEventArgs> OnEncryptionError;
        public event EventHandler<ErrorEventArgs> OnGeneralError;

        public NetworkServer(Configuration config)
        {
            _config = config;
            _stats = new Stats { StartTime = DateTime.UtcNow };
            _clients = new ConcurrentDictionary<string, Connection>();
        }

        public Stats GetStats()
        {
            lock (_statsLock)
            {
                _stats.ActiveConnections = _clients.Count;
                return _stats;
            }
        }

        public string IpAddress => _config != null ? _config.Host : string.Empty;
        public int Port => _config != null ? _config.Port : 0;

        public async Task StartAsync()
        {
            _serverCancellation = new CancellationTokenSource();

            if (_config.Protocol == ProtocolType.TCP)
            {
                await StartTcpServerAsync();
            }
            else
            {
                await StartUdpServerAsync();
            }
        }

        private async Task StartTcpServerAsync()
        {
            _tcpListener = new TcpListener(IPAddress.Parse(_config.Host), _config.Port);
            _tcpListener.Start();

            Console.WriteLine($"TCP Server started on {_config.Host}:{_config.Port}");

            while (!_serverCancellation.Token.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await _tcpListener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleTcpClientAsync(tcpClient), _serverCancellation.Token);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error accepting TCP client" });
                }
            }
        }

        public Dictionary<string, Connection> GetClients()
        {
            return _clients.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        private async Task StartUdpServerAsync()
        {
            _udpListener = new UdpClient(_config.Port);
            Console.WriteLine($"UDP Server started on {_config.Host}:{_config.Port}");

            while (!_serverCancellation.Token.IsCancellationRequested)
            {
                try
                {
                    var result = await _udpListener.ReceiveAsync();
                    _ = Task.Run(() => HandleUdpDataAsync(result), _serverCancellation.Token);
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error receiving UDP data" });
                }
            }
        }

        private async Task HandleTcpClientAsync(TcpClient tcpClient)
        {
            var clientId = Guid.NewGuid().ToString();
            var client = new Connection
            {
                Id = clientId,
                TcpClient = tcpClient,
                RemoteEndPoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint,
                ConnectedAt = DateTime.UtcNow,
                LastActive = DateTime.UtcNow,
                CancellationToken = new CancellationTokenSource()
            };

            try
            {
                // Configure TCP client
                tcpClient.NoDelay = !_config.EnableNagle;
                if (_config.EnableKeepAlive)
                {
                    tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                }

                Stream stream = tcpClient.GetStream();

                // Setup SSL if required
                if (_config.UseSsl)
                {
                    try
                    {
                        var sslStream = new SslStream(stream, false, userCertificateValidationCallback: _config.GetRemoteCertificateValidationCallback());
                        await sslStream.AuthenticateAsServerAsync(_config.Certificate, _config.MutuallyAuthenticate, SslProtocols.Tls12 | SslProtocols.Tls13, _config.CheckCertificateRevocation);
                        stream = sslStream;
                        client.IsSecure = true;
                    }
                    catch (Exception ex)
                    {
                        OnSslError?.Invoke(this, new ErrorEventArgs { ClientId = clientId, Exception = ex, Message = "SSL authentication failed" });
                        return;
                    }
                }

                // Setup AES encryption if required
                if (_config.UseAesEncryption)
                {
                    try
                    {
                        client.AesEncryption = Aes.Create();
                        client.AesEncryption.GenerateKey();
                        client.AesEncryption.GenerateIV();
                        client.IsEncrypted = true;

                        // Securely send raw AES key + IV + salt + password
                        await AesKeyExchange.SendAesKeyAsync(stream, client.AesEncryption, _config.AesPassword);
                    }
                    catch (Exception ex)
                    {
                        OnEncryptionError?.Invoke(this, new ErrorEventArgs
                        {
                            ClientId = clientId,
                            Exception = ex,
                            Message = "AES setup failed"
                        });
                        return;
                    }
                }

                client.Stream = stream;
                _clients[clientId] = client;

                lock (_statsLock)
                {
                    _stats.TotalConnections++;
                }

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = clientId, RemoteEndPoint = client.RemoteEndPoint });

                // Handle client communication
                await HandleClientCommunicationAsync(client);
            }
            catch (Exception ex)
            {
                OnGeneralError?.Invoke(this, new ErrorEventArgs { ClientId = clientId, Exception = ex, Message = "Error handling TCP client" });
            }
            finally
            {
                await DisconnectClientAsync(clientId);
            }
        }

        private async Task HandleUdpDataAsync(UdpReceiveResult result)
        {
            var clientKey = result.RemoteEndPoint.ToString();

            if (!_clients.TryGetValue(clientKey, out var client))
            {
                client = new Connection
                {
                    Id = clientKey,
                    RemoteEndPoint = result.RemoteEndPoint,
                    ConnectedAt = DateTime.UtcNow
                };
                _clients[clientKey] = client;

                lock (_statsLock)
                {
                    _stats.TotalConnections++;
                }

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = clientKey, RemoteEndPoint = result.RemoteEndPoint });
            }

            await ProcessReceivedDataAsync(client, result.Buffer);
        }

        private async Task HandleClientCommunicationAsync(Connection client)
        {
            var lengthBuffer = new byte[4]; // length prefix

            while (!client.CancellationToken.Token.IsCancellationRequested && client.TcpClient.Connected)
            {
                try
                {
                    byte[] data;

                    if (client.IsEncrypted && client.AesEncryption != null)
                    {
                        // Read 4-byte length first
                        int read = await ReadExactAsync(client.Stream, lengthBuffer, 4, client.CancellationToken.Token);
                        if (read == 0)
                        {
                            break;
                        }

                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(lengthBuffer);
                        }

                        int length = BitConverter.ToInt32(lengthBuffer, 0);

                        // Read full encrypted message
                        var encrypted = new byte[length];
                        await ReadExactAsync(client.Stream, encrypted, length, client.CancellationToken.Token);

                        // **Decrypt once here**
                        data = await DecryptDataAsync(encrypted, client.AesEncryption);
                    }
                    else
                    {
                        // Non-encrypted: just read raw bytes
                        data = new byte[_config.BufferSize];
                        int bytesRead = await client.Stream.ReadAsync(data, 0, data.Length, client.CancellationToken.Token);
                        if (bytesRead == 0)
                        {
                            break;
                        }

                        if (bytesRead < data.Length)
                        {
                            var tmp = new byte[bytesRead];
                            Array.Copy(data, tmp, bytesRead);
                            data = tmp;
                        }
                    }

                    await ProcessReceivedDataAsync(client, data);
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs
                    {
                        ClientId = client.Id,
                        Exception = ex,
                        Message = "Error reading from client"
                    });
                    break;
                }
            }
        }

        private async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int length, CancellationToken ct)
        {
            int offset = 0;
            while (offset < length)
            {
                int read = await stream.ReadAsync(buffer, offset, length - offset, ct);
                if (read == 0)
                {
                    return 0; // disconnected
                }

                offset += read;
            }
            return offset;
        }


        private async Task ProcessReceivedDataAsync(Connection client, byte[] data)
        {
            try
            {
                client.BytesReceived += data.Length;
                lock (_statsLock)
                {
                    _stats.BytesReceived += data.Length;
                    _stats.MessagesReceived++;
                }

                // Try to decode as string, fallback to binary
                bool isBinary = true;
                string stringData = null;

                try
                {
                    stringData = Encoding.UTF8.GetString(data);
                    if (Encoding.UTF8.GetBytes(stringData).Length == data.Length)
                    {
                        isBinary = false;
                    }
                }
                catch { }

                // Handle special commands
                if (!isBinary && stringData != null)
                {
                    if (stringData.StartsWith("NICKNAME:"))
                    {
                        var nickname = stringData.Substring(9);
                        client.Nickname = nickname;
                        OnConnectedWithNickname?.Invoke(this, new ConnectionEventArgs
                        {
                            ClientId = client.Id,
                            RemoteEndPoint = client.RemoteEndPoint,
                            Nickname = nickname
                        });
                        return;
                    }
                    else if (stringData.StartsWith("[NICKNAME]", StringComparison.OrdinalIgnoreCase))
                    {
                        var nickname = StringHelper.GetTextBetweenTags(stringData, "[NICKNAME]", "[/NICKNAME]");
                        if (string.IsNullOrWhiteSpace(nickname))
                        {
                            nickname = client.Id; // fallback to client ID if no valid nickname was provided
                        }
                        else
                        {
                            client.Nickname = nickname;
                        }
                        OnConnectedWithNickname?.Invoke(this, new ConnectionEventArgs
                        {
                            ClientId = client.Id,
                            RemoteEndPoint = client.RemoteEndPoint,
                            Nickname = nickname
                        });
                        return;
                    }
                    else if (stringData.Equals("DISCONNECT", StringComparison.OrdinalIgnoreCase))
                    {
                        await DisconnectClientAsync(client.Id);
                        return;
                    }
                }

                client.LastActive = DateTime.UtcNow;
                OnDataReceived?.Invoke(this, new DataReceivedEventArgs
                {
                    ClientId = client.Id,
                    Nickname = client.Nickname,
                    RemoteEndPoint = client.RemoteEndPoint,
                    Data = data,
                    StringData = stringData,
                    IsBinary = isBinary
                });
            }
            catch (Exception ex)
            {
                if (client.IsEncrypted)
                {
                    OnEncryptionError?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error processing data" });
                }
                else
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error processing data" });
                }
            }
        }


        public async Task SendToClientAsync(string clientId, byte[] data)
        {
            // Check if clientId is a guid
            if (Guid.TryParse(clientId, out _))
            {
                if (_clients.TryGetValue(clientId, out var client))
                {
                    await SendDataAsync(client, data);
                    return;
                }
            }

            // Check if clientId is an IP:Port format
            string[] parts = clientId.Split(':');
            if (parts.Length == 2)
            {
                if (IPAddress.TryParse(parts[0], out IPAddress ip) && int.TryParse(parts[1], out int port))
                {
                    IPEndPoint endPoint = new IPEndPoint(ip, port);
                    string clientKey = endPoint.ToString();

                    if (_clients.TryGetValue(clientKey, out var client))
                    {
                        // If inside async method, you can use await
                        await SendDataAsync(client, data);
                        return;
                    }
                }
            }

            // Check if the client is a nickname
            foreach (var kvp in _clients)
            {
                if (kvp.Value.Nickname != null && kvp.Value.Nickname.Equals(clientId, StringComparison.OrdinalIgnoreCase))
                {
                    await SendDataAsync(kvp.Value, data);
                    return;
                }
            }
        }

        public async Task SendToClientAsync(string clientId, string message)
        {
            await SendToClientAsync(clientId, Encoding.UTF8.GetBytes(message));
        }

        public async Task BroadcastAsync(byte[] data)
        {
            var tasks = new List<Task>();
            foreach (var client in _clients.Values)
            {
                tasks.Add(SendDataAsync(client, data));
            }
            await Task.WhenAll(tasks);
        }

        public async Task BroadcastAsync(string message)
        {
            await BroadcastAsync(Encoding.UTF8.GetBytes(message));
        }

        private async Task SendDataAsync(Connection client, byte[] data)
        {
            try
            {
                if (client.IsEncrypted && client.AesEncryption != null)
                {
                    // Encrypt payload
                    data = await EncryptDataAsync(data, client.AesEncryption);

                    // Prepend length for safe framing
                    var lengthPrefix = BitConverter.GetBytes(data.Length);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(lengthPrefix);
                    }

                    var framed = new byte[lengthPrefix.Length + data.Length];
                    Buffer.BlockCopy(lengthPrefix, 0, framed, 0, lengthPrefix.Length);
                    Buffer.BlockCopy(data, 0, framed, lengthPrefix.Length, data.Length);

                    data = framed; // replace the data with framed payload
                }

                if (_config.Protocol == ProtocolType.TCP)
                {
                    await client.Stream.WriteAsync(data, 0, data.Length);
                    await client.Stream.FlushAsync();
                }
                else
                {
                    await _udpListener.SendAsync(data, data.Length, client.RemoteEndPoint);
                }

                client.BytesSent += data.Length;
                lock (_statsLock)
                {
                    _stats.BytesSent += data.Length;
                    _stats.MessagesSent++;
                }
            }
            catch (Exception ex)
            {
                if (client.IsEncrypted)
                {
                    OnEncryptionError?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error encrypting/sending data" });
                }
                else
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error sending data" });
                }
            }
        }


        private async Task<byte[]> EncryptDataAsync(byte[] data, Aes aes)
        {
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data, 0, data.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        private async Task<byte[]> DecryptDataAsync(byte[] data, Aes aes)
        {
            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new MemoryStream(data))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var result = new MemoryStream())
            {
                await cs.CopyToAsync(result);
                return result.ToArray();
            }
        }

        private async Task DisconnectClientAsync(string clientId)
        {
            await Task.Run(() =>
            {
                if (_clients.TryRemove(clientId, out var client))
                {
                    try
                    {
                        client.CancellationToken?.Cancel();
                        client.TcpClient?.Close();
                        client.Stream?.Dispose();
                        client.AesEncryption?.Dispose();

                        OnDisconnected?.Invoke(this, new ConnectionEventArgs { ClientId = clientId, RemoteEndPoint = client.RemoteEndPoint, Nickname = client.Nickname });
                    }
                    catch (Exception ex)
                    {
                        OnGeneralError?.Invoke(this, new ErrorEventArgs { ClientId = clientId, Exception = ex, Message = "Error disconnecting client" });
                    }
                }
            });
        }

        public void Stop()
        {
            _serverCancellation?.Cancel();
            _tcpListener?.Stop();
            _udpListener?.Close();

            // Disconnect all clients
            var disconnectTasks = new List<Task>();
            foreach (var clientId in _clients.Keys.ToArray())
            {
                disconnectTasks.Add(DisconnectClientAsync(clientId));
            }
            Task.WaitAll(disconnectTasks.ToArray());
        }

        public void Dispose()
        {
            Stop();
            _serverCancellation?.Dispose();
        }
    }
}