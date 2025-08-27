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
    public class NetworkServer : IDisposable
    {
        private readonly Configuration _config;
        private readonly Stats _stats;
        private readonly ConcurrentDictionary<string, Connection> _clients;
        private TcpListener _tcpListener;
        private UdpClient _udpListener;
        private CancellationTokenSource _serverCancellation;
        private readonly object _statsLock = new object();
        private readonly object _serverLock = new object();

        private readonly ConcurrentDictionary<string, ConcurrentBag<string>> _rooms = new();
        private readonly ConcurrentDictionary<string, ConcurrentQueue<string>> _roomHistory = new();
        private readonly ConcurrentDictionary<string, string> _roomPasswords = new();
        private readonly ConcurrentDictionary<string, (int Count, DateTime Timestamp)> _rateLimits = new();
        private readonly int _maxMessagesPerSecond = 10;

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

        public string IpAddress => _config?.Host ?? string.Empty;
        public int Port => _config?.Port ?? 0;

        public async Task StartAsync()
        {
            lock (_serverLock)
            {
                if (_serverCancellation != null && !_serverCancellation.IsCancellationRequested)
                {
                    // Server is already running
                    return;
                }

                _serverCancellation = new CancellationTokenSource();
            }

            try
            {
                if (_config.Protocol == ProtocolType.TCP)
                {
                    await StartTcpServerAsync();
                }
                else
                {
                    await StartUdpServerAsync();
                }
            }
            catch (Exception ex)
            {
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error starting server" });
            }
        }

        private async Task StartTcpServerAsync()
        {
            lock (_serverLock)
            {
                if (_tcpListener != null)
                {
                    _tcpListener.Stop();
                }

                _tcpListener = new TcpListener(IPAddress.Parse(_config.Host), _config.Port);
                _tcpListener.Start();
            }

            Console.WriteLine($"TCP Server started on {_config.Host}:{_config.Port}");

            while (!_serverCancellation.Token.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await _tcpListener.AcceptTcpClientAsync();
                    _ = Task.Run(() => HandleTcpClientAsync(tcpClient), _serverCancellation.Token);
                }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error accepting TCP client" });
                }
            }
        }


        private readonly TimeSpan _udpCleanupInterval = TimeSpan.FromMinutes(1);

        private async Task CleanupInactiveUdpClientsAsync()
        {
            while (!_serverCancellation.Token.IsCancellationRequested)
            {
                var now = DateTime.UtcNow;
                foreach (var kvp in _clients.ToArray())
                {
                    var client = kvp.Value;
                    if (client.TcpClient == null && (now - client.LastActive) > TimeSpan.FromMinutes(5))
                    {
                        DisconnectClient(client.Id);
                    }
                }
                await Task.Delay(_udpCleanupInterval, _serverCancellation.Token);
            }
        }

        private bool CheckRateLimit(string clientId)
        {
            var now = DateTime.UtcNow;

            _rateLimits.TryGetValue(clientId, out var record);
            if ((now - record.Timestamp).TotalSeconds > 1)
            {
                record = (0, now);
            }

            record.Count++;
            _rateLimits[clientId] = record;

            return record.Count <= _maxMessagesPerSecond;
        }



        private async Task StartUdpServerAsync()
        {
            lock (_serverLock)
            {
                _udpListener?.Close();
                _udpListener = new UdpClient(_config.Port);
            }

            Console.WriteLine($"UDP Server started on {_config.Host}:{_config.Port}");
            _ = Task.Run(() => CleanupInactiveUdpClientsAsync(), _serverCancellation.Token);

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
                CancellationToken = new CancellationTokenSource(),
                SendLock = new SemaphoreSlim(1, 1)
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
                        var sslStream = new SslStream(stream, false, _config.GetRemoteCertificateValidationCallback());
                        await sslStream.AuthenticateAsServerAsync(
                            _config.Certificate,
                            _config.MutuallyAuthenticate,
                            SslProtocols.Tls12 | SslProtocols.Tls13,
                            _config.CheckCertificateRevocation
                        );
                        stream = sslStream;
                        client.IsSecure = true;
                    }
                    catch (Exception ex)
                    {
                        var handler = OnSslError;
                        handler?.Invoke(this, new ErrorEventArgs { ClientId = clientId, Exception = ex, Message = "SSL authentication failed" });
                        return;
                    }
                }

                if (_config.UseAesEncryption)
                {
                    try
                    {
                        client.AesEncryption = Aes.Create();
                        client.AesEncryption.KeySize = 256;
                        client.AesEncryption.BlockSize = 128;
                        client.AesEncryption.Mode = CipherMode.CBC;
                        client.AesEncryption.Padding = PaddingMode.PKCS7;
                        client.IsEncrypted = true;

                        await AesKeyExchange.SendAesKeyAsync(stream, client.AesEncryption, _config.AesPassword);
                    }
                    catch (Exception ex)
                    {
                        var handler = OnEncryptionError;
                        handler?.Invoke(this, new ErrorEventArgs { ClientId = clientId, Exception = ex, Message = "AES setup failed" });
                        return;
                    }
                }

                client.Stream = stream;
                _clients[clientId] = client;

                lock (_statsLock) { _stats.TotalConnections++; }

                var connectedHandler = OnConnected;
                connectedHandler?.Invoke(this, new ConnectionEventArgs { ClientId = clientId, RemoteEndPoint = client.RemoteEndPoint });

                await HandleClientCommunicationAsync(client);
            }
            catch (Exception ex)
            {
                var handler = OnGeneralError;
                handler?.Invoke(this, new ErrorEventArgs { ClientId = clientId, Exception = ex, Message = "Error handling TCP client" });
            }
            finally
            {
                DisconnectClient(clientId);
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
                    ConnectedAt = DateTime.UtcNow,
                    SendLock = new SemaphoreSlim(1, 1)
                };
                _clients[clientKey] = client;

                lock (_statsLock) { _stats.TotalConnections++; }

                var handler = OnConnected;
                handler?.Invoke(this, new ConnectionEventArgs { ClientId = clientKey, RemoteEndPoint = result.RemoteEndPoint });
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
                        if (await ReadExactAsync(client.Stream, lengthBuffer, 4, client.CancellationToken.Token) == 0)
                        {
                            break;
                        }

                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(lengthBuffer);
                        }

                        int length = BitConverter.ToInt32(lengthBuffer, 0);

                        var encrypted = new byte[length];
                        await ReadExactAsync(client.Stream, encrypted, length, client.CancellationToken.Token);

                        data = await AesCryptoHelpers.DecryptDataAsync(encrypted, client.AesEncryption);
                    }
                    else
                    {
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
                    var handler = OnGeneralError;
                    handler?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error reading from client" });
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
                    return 0;
                }

                offset += read;
            }
            return offset;
        }

        private async Task ProcessReceivedDataAsync(Connection client, byte[] data)
        {
            try
            {
                if (!CheckRateLimit(client.Id))
                {
                    // Throttle the client
                    await Task.Delay(100);
                    return;
                }

                client.BytesReceived += data.Length;
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
                    isBinary = Encoding.UTF8.GetBytes(stringData).Length != data.Length;
                }
                catch { }

                if (!isBinary && stringData != null)
                {
                    if (stringData.StartsWith("NICKNAME:"))
                    {
                        client.Nickname = stringData.Substring(9);
                        var handler = OnConnectedWithNickname;
                        handler?.Invoke(this, new ConnectionEventArgs
                        {
                            ClientId = client.Id,
                            RemoteEndPoint = client.RemoteEndPoint,
                            Nickname = client.Nickname
                        });
                        return;
                    }
                    else if (stringData.Equals("DISCONNECT", StringComparison.OrdinalIgnoreCase))
                    {
                        DisconnectClient(client.Id);
                        return;
                    }
                    else if (stringData.StartsWith("JOIN_ROOM:"))
                    {
                        string roomName = stringData.Substring(10);
                        var bag = _rooms.GetOrAdd(roomName, _ => new ConcurrentBag<string>());
                        if (!bag.Contains(client.Id))
                        {
                            bag.Add(client.Id);
                        }

                        return;
                    }
                    else if (stringData.StartsWith("LEAVE_ROOM:"))
                    {
                        string roomName = stringData.Substring(11);
                        if (_rooms.TryGetValue(roomName, out var bag))
                        {
                            _rooms[roomName] = new ConcurrentBag<string>(bag.Where(id => id != client.Id));
                        }
                        return;
                    }
                    else if (stringData.StartsWith("ROOM_MSG:"))
                    {
                        var parts = stringData.Substring(9).Split(new[] { ":" }, 2, StringSplitOptions.None);
                        if (parts.Length == 2)
                        {
                            string roomName = parts[0];
                            string msg = parts[1];

                            if (_rooms.TryGetValue(roomName, out var clients))
                            {
                                // Broadcast to room
                                var tasks = clients.Where(id => _clients.ContainsKey(id))
                                                   .Select(id => SendDataAsync(_clients[id], Encoding.UTF8.GetBytes($"{client.Nickname}:{msg}")));
                                await Task.WhenAll(tasks);

                                // Add to room history
                                var history = _roomHistory.GetOrAdd(roomName, _ => new ConcurrentQueue<string>());
                                history.Enqueue($"{client.Nickname}:{msg}");
                                while (history.Count > 100)
                                {
                                    history.TryDequeue(out _);
                                }
                            }
                        }
                        return;
                    }
                    else
                    {
                        await HandleCommand(client, stringData);
                    }
                }

                client.LastActive = DateTime.UtcNow;
                var dataHandler = OnDataReceived;
                dataHandler?.Invoke(this, new DataReceivedEventArgs
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
                var handler = client.IsEncrypted ? OnEncryptionError : OnGeneralError;
                handler?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error processing data", Nickname = client.Nickname });
            }
        }

        private async Task SendDataAsync(Connection client, byte[] data)
        {
            await client.SendLock.WaitAsync();
            try
            {
                if (client.IsEncrypted && client.AesEncryption != null)
                {
                    data = await AesCryptoHelpers.EncryptDataAsync(data, client.AesEncryption);
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

                client.BytesSent += data.Length;
                lock (_statsLock)
                {
                    _stats.BytesSent += data.Length;
                    _stats.MessagesSent++;
                }
            }
            catch (Exception ex)
            {
                var handler = client.IsEncrypted ? OnEncryptionError : OnGeneralError;
                handler?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error sending data", Nickname = client.Nickname });
            }
            finally
            {
                client.SendLock.Release();
            }
        }

        public async Task SendFileAsync(Connection client, byte[] fileData, int chunkSize = 8192)
        {
            int offset = 0;
            while (offset < fileData.Length)
            {
                int size = Math.Min(chunkSize, fileData.Length - offset);
                var chunk = new byte[size];
                Array.Copy(fileData, offset, chunk, 0, size);
                await SendDataAsync(client, chunk);
                offset += size;
            }
        }

        public void AddMessageToRoomHistory(string roomName, string message)
        {
            var queue = _roomHistory.GetOrAdd(roomName, _ => new ConcurrentQueue<string>());
            queue.Enqueue(message);
            if (queue.Count > 100)
            {
                queue.TryDequeue(out _);
            }
        }

        public bool SetRoomPassword(string roomName, string password)
        {
            _roomPasswords[roomName] = password;
            return true;
        }

        public bool JoinRoomWithPassword(string clientId, string roomName, string password)
        {
            if (_roomPasswords.TryGetValue(roomName, out var storedPassword) && storedPassword == password)
            {
                JoinRoom(clientId, roomName);
                return true;
            }
            return false;
        }


        public IEnumerable<string> GetRoomHistory(string roomName)
        {
            if (_roomHistory.TryGetValue(roomName, out var queue))
            {
                return queue.ToArray();
            }

            return Enumerable.Empty<string>();
        }

        public async Task SendPrivateMessageAsync(string fromNickname, string toNickname, string message)
        {
            var tasks = _clients.Values
                .Where(c => !string.IsNullOrEmpty(c.Nickname) && c.Nickname.Equals(toNickname, StringComparison.OrdinalIgnoreCase))
                .Select(c => SendDataAsync(c, Encoding.UTF8.GetBytes($"[PM from {fromNickname}]: {message}")))
                .ToArray();
            await Task.WhenAll(tasks);
        }


        public void GetAllClients(out List<Connection> clients)
        {
            clients = _clients.Values.ToList();
        }

        public Connection GetClientById(string clientId)
        {
            if (_clients.TryGetValue(clientId, out var client))
            {
                return client;
            }
            return _clients.Values.FirstOrDefault(c => c.Nickname != null && c.Nickname.Equals(clientId, StringComparison.OrdinalIgnoreCase));
        }

        public async Task SendToClientAsync(string clientId, byte[] data)
        {
            if (_clients.TryGetValue(clientId, out var client))
            {
                await SendDataAsync(client, data);
                return;
            }

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
            var tasks = _clients.Values.Select(c => SendDataAsync(c, data)).ToArray();
            await Task.WhenAll(tasks);
        }

        public async Task BroadcastAsync(string message)
        {
            await BroadcastAsync(Encoding.UTF8.GetBytes(message));
        }

        private void DisconnectClient(string clientId)
        {
            if (_clients.TryRemove(clientId, out var client))
            {
                try
                {
                    CleanupClientFromRooms(clientId);

                    client.CancellationToken?.Cancel();
                    client.TcpClient?.Close();
                    client.Stream?.Dispose();
                    client.AesEncryption?.Dispose();

                    foreach (var room in _rooms.Keys.ToList())
                    {
                        if (_rooms.TryGetValue(room, out var bag))
                        {
                            _rooms[room] = new ConcurrentBag<string>(bag.Where(id => id != clientId));
                        }
                    }

                    var handler = OnDisconnected;
                    handler?.Invoke(this, new ConnectionEventArgs { ClientId = client.Id, RemoteEndPoint = client.RemoteEndPoint, Nickname = client.Nickname });
                }
                catch (Exception ex)
                {
                    var handler = OnGeneralError;
                    handler?.Invoke(this, new ErrorEventArgs { ClientId = client.Id, Exception = ex, Message = "Error disconnecting client", Nickname = client.Nickname });
                }
            }
        }

        public void JoinRoom(string clientId, string roomName)
        {
            var bag = _rooms.GetOrAdd(roomName, _ => new ConcurrentBag<string>());
            bag.Add(clientId);
        }

        public void LeaveRoom(string clientId, string roomName)
        {
            if (_rooms.TryGetValue(roomName, out var bag))
            {
                var newBag = new ConcurrentBag<string>(bag.Where(id => id != clientId));
                _rooms[roomName] = newBag;
            }
        }

        public async Task BroadcastToNicknameAsync(string nickname, byte[] data)
        {
            var tasks = _clients.Values
                .Where(c => !string.IsNullOrEmpty(c.Nickname) && c.Nickname.Equals(nickname, StringComparison.OrdinalIgnoreCase))
                .Select(c => SendDataAsync(c, data))
                .ToArray();
            await Task.WhenAll(tasks);
        }

        public async Task BroadcastToNicknameAsync(string nickname, string message)
        {
            await BroadcastToNicknameAsync(nickname, Encoding.UTF8.GetBytes(message));
        }

        public async Task BroadcastToRoomAsync(string roomName, byte[] data)
        {
            if (!_rooms.TryGetValue(roomName, out var clients))
            {
                return;
            }

            var tasks = clients.Where(id => _clients.ContainsKey(id))
                               .Select(id => SendDataAsync(_clients[id], data))
                               .ToArray();
            await Task.WhenAll(tasks);
        }

        public async Task BroadcastToRoomExceptAsync(string roomName, byte[] data, string exceptClientId)
        {
            if (!_rooms.TryGetValue(roomName, out var clients))
            {
                return;
            }

            var tasks = clients
                .Where(id => _clients.ContainsKey(id) && id != exceptClientId)
                .Select(id => SendDataAsync(_clients[id], data))
                .ToArray();

            await Task.WhenAll(tasks);
        }

        private readonly ConcurrentDictionary<string, Func<Connection, string, Task>> _commands = new();

        public void RegisterCommand(string command, Func<Connection, string, Task> handler)
        {
            _commands[command] = handler;
        }

        private async Task HandleCommand(Connection client, string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                return;
            }

            var parts = commandLine.Split(' ');
            var cmd = parts[0].ToUpperInvariant();
            var args = parts.Length > 1 ? parts[1] : string.Empty;

            if (_commands.TryGetValue(cmd, out var handler))
            {
                await handler(client, args);
            }
        }


        public async Task BroadcastToRoomAsync(string roomName, string message)
        {
            await BroadcastToRoomAsync(roomName, Encoding.UTF8.GetBytes(message));
        }

        public void Stop()
        {
            lock (_serverLock)
            {
                _serverCancellation?.Cancel();
                _tcpListener?.Stop();
                _udpListener?.Close();
            }

            foreach (var clientId in _clients.Keys.ToArray())
            {
                DisconnectClient(clientId);
            }
        }

        private void CleanupClientFromRooms(string clientId)
        {
            foreach (var room in _rooms.Keys.ToList())
            {
                LeaveRoom(clientId, room);
            }
        }

        public void Dispose() => Stop();
    }
}
