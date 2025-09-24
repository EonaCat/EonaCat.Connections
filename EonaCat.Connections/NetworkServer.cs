using EonaCat.Connections.EventArguments;
using EonaCat.Connections.Helpers;
using EonaCat.Connections.Models;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
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
        private readonly object _tcpLock = new object();
        private readonly object _udpLock = new object();

        public event EventHandler<ConnectionEventArgs> OnConnected;
        public event EventHandler<ConnectionEventArgs> OnConnectedWithNickname;
        public event EventHandler<DataReceivedEventArgs> OnDataReceived;
        public event EventHandler<ConnectionEventArgs> OnDisconnected;
        public event EventHandler<ErrorEventArgs> OnSslError;
        public event EventHandler<ErrorEventArgs> OnEncryptionError;
        public event EventHandler<ErrorEventArgs> OnGeneralError;

        public bool IsStarted => _serverCancellation != null && !_serverCancellation.IsCancellationRequested;
        public bool IsSecure => _config != null && (_config.UseSsl || _config.UseAesEncryption);
        public bool IsEncrypted => _config != null && _config.UseAesEncryption;
        public int ActiveConnections => _clients.Count;
        public long TotalConnections => _stats.TotalConnections;
        public long BytesSent => _stats.BytesSent;
        public long BytesReceived => _stats.BytesReceived;
        public long MessagesSent => _stats.MessagesSent;
        public long MessagesReceived => _stats.MessagesReceived;
        public double MessagesPerSecond => _stats.MessagesPerSecond;
        public TimeSpan Uptime => _stats.Uptime;
        public DateTime StartTime => _stats.StartTime;
        public int MaxConnections => _config != null ? _config.MaxConnections : 0;
        public ProtocolType Protocol => _config != null ? _config.Protocol : ProtocolType.TCP;
        private int _tcpRunning = 0;
        private int _udpRunning = 0;

        private readonly List<IServerPlugin> _plugins = new List<IServerPlugin>();
        public void RegisterPlugin(IServerPlugin plugin) => _plugins.Add(plugin);
        public void UnregisterPlugin(IServerPlugin plugin) => _plugins.Remove(plugin);
        private void InvokePlugins(Action<IServerPlugin> action)
        {
            foreach (var plugin in _plugins)
            {
                try { action(plugin); }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs
                    {
                        Exception = ex,
                        Message = $"Plugin {plugin.Name} failed"
                    });
                }
            }
        }

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

            InvokePlugins(p => p.OnServerStarted(this));
        }

        public async Task StartTcpServerAsync()
        {
            if (Interlocked.CompareExchange(ref _tcpRunning, 1, 0) == 1)
            {
                Console.WriteLine("TCP Server is already running.");
                return;
            }

            try
            {
                lock (_tcpLock)
                {
                    _tcpListener = new TcpListener(IPAddress.Parse(_config.Host), _config.Port);
                    _tcpListener.Start();
                }

                Console.WriteLine($"TCP Server started on {_config.Host}:{_config.Port}");

                while (!_serverCancellation.Token.IsCancellationRequested)
                {
                    TcpClient? tcpClient = null;

                    try
                    {
                        lock (_tcpLock)
                        {
                            if (_tcpListener == null)
                            {
                                break;
                            }
                        }

                        tcpClient = await _tcpListener!.AcceptTcpClientAsync().ConfigureAwait(false);
                        _ = Task.Run(() => HandleTcpClientAsync(tcpClient), _serverCancellation.Token);
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (InvalidOperationException ex) when (ex.Message.Contains("Not listening"))
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        OnGeneralError?.Invoke(this, new ErrorEventArgs
                        {
                            Exception = ex,
                            Message = "Error accepting TCP client"
                        });
                    }
                }
            }
            finally
            {
                StopTcpServer();
            }
        }

        private void StopTcpServer()
        {
            lock (_tcpLock)
            {
                _tcpListener?.Stop();
                _tcpListener = null;
            }

            Interlocked.Exchange(ref _tcpRunning, 0);
        }

        public Dictionary<string, Connection> GetClients()
        {
            return _clients.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        public async Task StartUdpServerAsync()
        {
            if (Interlocked.CompareExchange(ref _udpRunning, 1, 0) == 1)
            {
                Console.WriteLine("UDP Server is already running.");
                return;
            }

            try
            {
                lock (_udpLock)
                {
                    _udpListener = new UdpClient(_config.Port);
                }

                Console.WriteLine($"UDP Server started on {_config.Host}:{_config.Port}");

                while (!_serverCancellation.Token.IsCancellationRequested)
                {
                    try
                    {
                        UdpReceiveResult result;

                        lock (_udpLock)
                        {
                            if (_udpListener == null)
                            {
                                break;
                            }
                        }

                        result = await _udpListener!.ReceiveAsync().ConfigureAwait(false);

                        _ = Task.Run(() => HandleUdpDataAsync(result), _serverCancellation.Token);
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        OnGeneralError?.Invoke(this, new ErrorEventArgs
                        {
                            Exception = ex,
                            Message = "Error receiving UDP data"
                        });
                    }
                }
            }
            finally
            {
                StopUdpServer();
            }
        }

        private void StopUdpServer()
        {
            lock (_udpLock)
            {
                _udpListener?.Close();
                _udpListener?.Dispose();
                _udpListener = null;
            }

            Interlocked.Exchange(ref _udpRunning, 0);
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
                tcpClient.NoDelay = !_config.EnableNagle;
                if (_config.EnableKeepAlive)
                {
                    tcpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                }

                Stream stream = tcpClient.GetStream();

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
                        OnSslError?.Invoke(this, new ErrorEventArgs { ClientId = clientId, Nickname = client.Nickname, Exception = ex, Message = "SSL authentication failed" });
                        return;
                    }
                }

                if (_config.UseAesEncryption)
                {
                    try
                    {
                        client.AesEncryption = Aes.Create();
                        client.AesEncryption.GenerateKey();
                        client.AesEncryption.GenerateIV();
                        client.IsEncrypted = true;

                        await AesKeyExchange.SendAesKeyAsync(stream, client.AesEncryption, _config.AesPassword);
                    }
                    catch (Exception ex)
                    {
                        OnEncryptionError?.Invoke(this, new ErrorEventArgs
                        {
                            ClientId = clientId,
                            Nickname = client.Nickname,
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

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = clientId, RemoteEndPoint = client.RemoteEndPoint, Nickname = client.Nickname });
                InvokePlugins(p => p.OnClientConnected(client));

                await HandleClientCommunicationAsync(client);
            }
            catch (Exception ex)
            {
                await DisconnectClientAsync(clientId, DisconnectReason.Error, ex);
            }
            finally
            {
                await DisconnectClientAsync(clientId, DisconnectReason.Unknown);
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
                InvokePlugins(p => p.OnClientConnected(client));
            }

            await ProcessReceivedDataAsync(client, result.Buffer);
        }

        private async Task HandleClientCommunicationAsync(Connection client)
        {
            var lengthBuffer = new byte[4];

            while (!client.CancellationToken.Token.IsCancellationRequested && client.TcpClient.Connected)
            {
                try
                {
                    byte[] data;

                    if (client.IsEncrypted && client.AesEncryption != null)
                    {
                        int read = await ReadExactAsync(client.Stream, lengthBuffer, 4, client, client.CancellationToken.Token);
                        if (read == 0)
                        {
                            break;
                        }

                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(lengthBuffer);
                        }

                        int length = BitConverter.ToInt32(lengthBuffer, 0);

                        var encrypted = new byte[length];
                        await ReadExactAsync(client.Stream, encrypted, length, client, client.CancellationToken.Token);

                        data = await AesKeyExchange.DecryptDataAsync(encrypted, client.AesEncryption);
                    }
                    else
                    {
                        data = new byte[_config.BufferSize];

                        await client.ReadLock.WaitAsync(client.CancellationToken.Token); // NEW
                        try
                        {
                            int bytesRead = await client.Stream.ReadAsync(data, 0, data.Length, client.CancellationToken.Token);
                            if (bytesRead == 0)
                            {
                                await DisconnectClientAsync(client.Id, DisconnectReason.RemoteClosed);
                                return;
                            }

                            if (bytesRead < data.Length)
                            {
                                var tmp = new byte[bytesRead];
                                Array.Copy(data, tmp, bytesRead);
                                data = tmp;
                            }
                        }
                        catch (IOException ioEx)
                        {
                            await DisconnectClientAsync(client.Id, DisconnectReason.RemoteClosed, ioEx);
                            return;
                        }
                        catch (SocketException sockEx)
                        {
                            await DisconnectClientAsync(client.Id, DisconnectReason.Error, sockEx);
                            return;
                        }
                        catch (OperationCanceledException)
                        {
                            await DisconnectClientAsync(client.Id, DisconnectReason.Timeout);
                            return;
                        }
                        catch (Exception ex)
                        {
                            await DisconnectClientAsync(client.Id, DisconnectReason.Error, ex);
                            return;
                        }
                        finally
                        {
                            client.ReadLock.Release();
                        }
                    }

                    await ProcessReceivedDataAsync(client, data);
                }
                catch (IOException ioEx)
                {
                    await DisconnectClientAsync(client.Id, DisconnectReason.RemoteClosed, ioEx);
                }
                catch (SocketException sockEx)
                {
                    await DisconnectClientAsync(client.Id, DisconnectReason.Error, sockEx);
                }
                catch (Exception ex)
                {
                    await DisconnectClientAsync(client.Id, DisconnectReason.Error, ex);
                }
            }
        }

        private async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int length, Connection client, CancellationToken ct)
        {
            await client.ReadLock.WaitAsync(ct); // NEW
            try
            {
                int offset = 0;
                while (offset < length)
                {
                    int read = await stream.ReadAsync(buffer, offset, length - offset, ct);
                    if (read == 0)
                    {
                        return 0;
                    }

                    offset += read;
                }
                return offset;
            }
            finally
            {
                client.ReadLock.Release();
            }
        }


        private async Task ProcessReceivedDataAsync(Connection client, byte[] data)
        {
            try
            {
                client.AddBytesReceived(data.Length);
                lock (_statsLock)
                {
                    _stats.BytesReceived += data.Length;
                    _stats.MessagesReceived++;
                }

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
                        _clients[client.Id] = client;
                        return;
                    }
                    else if (stringData.StartsWith("[NICKNAME]", StringComparison.OrdinalIgnoreCase))
                    {
                        var nickname = StringHelper.GetTextBetweenTags(stringData, "[NICKNAME]", "[/NICKNAME]");
                        if (string.IsNullOrWhiteSpace(nickname))
                        {
                            nickname = client.Id;
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
                        _clients[client.Id] = client;
                        return;
                    }
                    else if (stringData.Equals("DISCONNECT", StringComparison.OrdinalIgnoreCase))
                    {
                        await DisconnectClientAsync(client.Id, DisconnectReason.ClientRequested);
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
                InvokePlugins(p => p.OnDataReceived(client, data, stringData, isBinary));
            }
            catch (Exception ex)
            {
                if (client.IsEncrypted)
                {
                    OnEncryptionError?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Nickname = client.Nickname, Exception = ex, Message = "Error processing data" });
                }
                else
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Nickname = client.Nickname, Exception = ex, Message = "Error processing data" });
                }
            }
        }

        public async Task SendToClientAsync(string clientId, byte[] data)
        {
            var client = GetClient(clientId);
            if (client != null && client.Count > 0)
            {
                foreach (var current in client)
                {
                    await SendDataAsync(current, data);
                }
            }
        }

        public async Task SendToClientAsync(string clientId, string message)
        {
            await SendToClientAsync(clientId, Encoding.UTF8.GetBytes(message));
        }

        public async Task SendFromClientToClientAsync(string fromClientId, string toClientId, byte[] data)
        {
            var fromClient = GetClient(fromClientId);
            var toClient = GetClient(toClientId);
            if (fromClient != null && toClient != null && fromClient.Count > 0 && toClient.Count > 0)
            {
                foreach (var current in toClient)
                {
                    await SendDataAsync(current, data);
                }
            }
        }

        public async Task SendFromClientToClientAsync(string fromClientId, string toClientId, string message)
        {
            await SendFromClientToClientAsync(fromClientId, toClientId, Encoding.UTF8.GetBytes(message));
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
            await client.SendLock.WaitAsync();
            try
            {
                if (client.IsEncrypted && client.AesEncryption != null)
                {
                    data = await AesKeyExchange.EncryptDataAsync(data, client.AesEncryption);

                    var lengthPrefix = BitConverter.GetBytes(data.Length);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(lengthPrefix);
                    }

                    var framed = new byte[lengthPrefix.Length + data.Length];
                    Buffer.BlockCopy(lengthPrefix, 0, framed, 0, lengthPrefix.Length);
                    Buffer.BlockCopy(data, 0, framed, lengthPrefix.Length, data.Length);
                    data = framed;
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

                client.AddBytesSent(data.Length);
                lock (_statsLock)
                {
                    _stats.BytesSent += data.Length;
                    _stats.MessagesSent++;
                }
            }
            catch (Exception ex)
            {
                var handler = client.IsEncrypted ? OnEncryptionError : OnGeneralError;
                handler?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Nickname = client.Nickname, Exception = ex, Message = "Error sending data" });
            }
            finally
            {
                client.SendLock.Release();
            }
        }

        public async Task DisconnectClientAsync(string clientId, DisconnectReason reason = DisconnectReason.Unknown, Exception exception = null)
        {
            if (!_clients.TryRemove(clientId, out var client))
            {
                return;
            }

            if (!client.MarkDisconnected())
            {
                return;
            }

            await Task.Run(() =>
            {
                try
                {
                    client.CancellationToken?.Cancel();
                    client.TcpClient?.Close();
                    client.Stream?.Dispose();
                    client.AesEncryption?.Dispose();
                    client.SendLock.Dispose();

                    Volatile.Read(ref OnDisconnected)?.Invoke(this,
                        new ConnectionEventArgs
                        {
                            ClientId = clientId,
                            Nickname = client.Nickname,
                            RemoteEndPoint = client.RemoteEndPoint,
                            Reason = ConnectionEventArgs.Determine(reason, exception),
                            Exception = exception
                        });

                    InvokePlugins(p => p.OnClientDisconnected(client, reason, exception));
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs
                    {
                        ClientId = clientId,
                        Nickname = client.Nickname,
                        Exception = ex,
                        Message = "Error disconnecting client"
                    });
                }
            });
        }

        public List<Connection> GetClient(string clientId)
        {
            var result = new HashSet<Connection>();

            if (Guid.TryParse(clientId, out _))
            {
                if (_clients.TryGetValue(clientId, out var client))
                {
                    result.Add(client);
                }
            }

            string[] parts = clientId.Split(':');
            if (parts.Length == 2 &&
                IPAddress.TryParse(parts[0], out IPAddress ip) &&
                int.TryParse(parts[1], out int port))
            {
                var endPoint = new IPEndPoint(ip, port);
                string clientKey = endPoint.ToString();

                if (_clients.TryGetValue(clientKey, out var client))
                {
                    result.Add(client);
                }
            }

            foreach (var kvp in _clients)
            {
                if (kvp.Value.Nickname != null &&
                    kvp.Value.Nickname.Equals(clientId, StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(kvp.Value);
                }
            }

            return result.ToList();
        }

        public void Stop()
        {
            _serverCancellation?.Cancel();
            _tcpListener?.Stop();
            _udpListener?.Close();

            var disconnectTasks = _clients.Keys.ToArray()
                .Select(id => DisconnectClientAsync(id, DisconnectReason.ServerShutdown))
                .ToList();

            Task.WaitAll(disconnectTasks.ToArray());

            InvokePlugins(p => p.OnServerStopped(this));
        }

        public void Dispose()
        {
            Stop();
            _serverCancellation?.Dispose();
        }
    }
}
