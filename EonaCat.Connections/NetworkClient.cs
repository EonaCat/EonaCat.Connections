using EonaCat.Connections.EventArguments;
using EonaCat.Connections.Helpers;
using EonaCat.Connections.Models;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ErrorEventArgs = EonaCat.Connections.EventArguments.ErrorEventArgs;

namespace EonaCat.Connections
{
    public class NetworkClient : IDisposable
    {
        private readonly Configuration _config;
        private TcpClient _tcpClient;
        private UdpClient _udpClient;
        private Stream _stream;
        private Aes _aesEncryption;
        private CancellationTokenSource _cancellation;
        private bool _isConnected;

        private readonly object _stateLock = new object();
        private readonly SemaphoreSlim _sendLock = new SemaphoreSlim(1, 1);

        private readonly HashSet<string> _joinedRooms = new();

        public bool IsConnected
        {
            get { lock (_stateLock)
                {
                    return _isConnected;
                }
            }
            private set { lock (_stateLock)
                {
                    _isConnected = value;
                }
            }
        }

        public bool IsAutoReconnecting { get; private set; }

        public event EventHandler<ConnectionEventArgs> OnConnected;
        public event EventHandler<DataReceivedEventArgs> OnDataReceived;
        public event EventHandler<ConnectionEventArgs> OnDisconnected;
        public event EventHandler<ErrorEventArgs> OnSslError;
        public event EventHandler<ErrorEventArgs> OnEncryptionError;
        public event EventHandler<ErrorEventArgs> OnGeneralError;

        public string IpAddress => _config?.Host ?? string.Empty;
        public int Port => _config?.Port ?? 0;

        public NetworkClient(Configuration config) => _config = config;

        public async Task ConnectAsync()
        {
            lock (_stateLock)
            {
                _cancellation?.Cancel();
                _cancellation = new CancellationTokenSource();
            }

            if (_config.Protocol == ProtocolType.TCP)
            {
                await ConnectTcpAsync();
            }
            else
            {
                await ConnectUdpAsync();
            }
        }

        private async Task ConnectTcpAsync()
        {
            try
            {
                var client = new TcpClient();
                await client.ConnectAsync(_config.Host, _config.Port);

                Stream stream = client.GetStream();

                if (_config.UseSsl)
                {
                    try
                    {
                        var sslStream = new SslStream(stream, false, _config.GetRemoteCertificateValidationCallback());
                        if (_config.Certificate != null)
                        {
                            sslStream.AuthenticateAsClient(_config.Host, new X509CertificateCollection { _config.Certificate }, _config.CheckCertificateRevocation);
                        }
                        else
                        {
                            sslStream.AuthenticateAsClient(_config.Host);
                        }

                        stream = sslStream;
                    }
                    catch (Exception ex)
                    {
                        OnSslError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "SSL authentication failed" });
                        return;
                    }
                }

                if (_config.UseAesEncryption)
                {
                    try
                    {
                        _aesEncryption = await AesKeyExchange.ReceiveAesKeyAsync(stream, _config.AesPassword);
                    }
                    catch (Exception ex)
                    {
                        OnEncryptionError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "AES setup failed" });
                        return;
                    }
                }

                lock (_stateLock)
                {
                    _tcpClient = client;
                    _stream = stream;
                    IsConnected = true;
                }

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });

                _ = Task.Run(() => ReceiveDataAsync(_cancellation.Token), _cancellation.Token);
            }
            catch (Exception ex)
            {
                IsConnected = false;
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Failed to connect" });
                _ = Task.Run(() => AutoReconnectAsync());
            }
        }

        private async Task ConnectUdpAsync()
        {
            try
            {
                var client = new UdpClient();
                client.Connect(_config.Host, _config.Port);

                lock (_stateLock)
                {
                    _udpClient = client;
                    IsConnected = true;
                }

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });

                _ = Task.Run(() => ReceiveUdpDataAsync(_cancellation.Token), _cancellation.Token);
            }
            catch (Exception ex)
            {
                IsConnected = false;
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Failed to connect UDP" });
            }
        }

        private async Task ReceiveDataAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && IsConnected)
            {
                try
                {
                    byte[] data;

                    if (_config.UseAesEncryption && _aesEncryption != null)
                    {
                        var lengthBuffer = new byte[4];
                        if (await ReadExactAsync(_stream, lengthBuffer, 4, ct) == 0)
                        {
                            break;
                        }

                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(lengthBuffer);
                        }

                        int length = BitConverter.ToInt32(lengthBuffer, 0);

                        var encrypted = new byte[length];
                        await ReadExactAsync(_stream, encrypted, length, ct);

                        data = await AesCryptoHelpers.DecryptDataAsync(encrypted, _aesEncryption);
                    }
                    else
                    {
                        data = new byte[_config.BufferSize];
                        int bytesRead = await _stream.ReadAsync(data, 0, data.Length, ct);
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

                    await ProcessReceivedDataAsync(data);
                }
                catch (Exception ex)
                {
                    IsConnected = false;
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error receiving data" });
                    _ = Task.Run(() => AutoReconnectAsync());
                    break;
                }
            }

            await DisconnectAsync();
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

        private async Task ReceiveUdpDataAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && IsConnected)
            {
                try
                {
                    var result = await _udpClient.ReceiveAsync();
                    await ProcessReceivedDataAsync(result.Buffer);
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error receiving UDP data" });
                    IsConnected = false;
                    _ = Task.Run(() => AutoReconnectAsync());
                    break;
                }
            }
        }

        private async Task ProcessReceivedDataAsync(byte[] data)
        {
            try
            {
                string stringData = null;
                bool isBinary = true;

                try
                {
                    stringData = Encoding.UTF8.GetString(data);
                    isBinary = Encoding.UTF8.GetBytes(stringData).Length != data.Length;
                }
                catch { }

                OnDataReceived?.Invoke(this, new DataReceivedEventArgs
                {
                    ClientId = "server",
                    Data = data,
                    StringData = stringData,
                    IsBinary = isBinary
                });
            }
            catch (Exception ex)
            {
                var handler = _config.UseAesEncryption ? OnEncryptionError : OnGeneralError;
                handler?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error processing data" });
            }
        }

        public async Task SendAsync(byte[] data)
        {
            if (!IsConnected)
            {
                return;
            }

            await _sendLock.WaitAsync();
            try
            {
                if (_config.UseAesEncryption && _aesEncryption != null)
                {
                    data = await AesCryptoHelpers.EncryptDataAsync(data, _aesEncryption);

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
                    await _stream.WriteAsync(data, 0, data.Length);
                    await _stream.FlushAsync();
                }
                else
                {
                    await _udpClient.SendAsync(data, data.Length);
                }
            }
            catch (Exception ex)
            {
                var handler = _config.UseAesEncryption ? OnEncryptionError : OnGeneralError;
                handler?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error sending data" });
            }
            finally
            {
                _sendLock.Release();
            }
        }

        /// <summary>Join a room (server should recognize this command)</summary>
        public async Task JoinRoomAsync(string roomName)
        {
            if (string.IsNullOrWhiteSpace(roomName) || _joinedRooms.Contains(roomName))
            {
                return;
            }

            _joinedRooms.Add(roomName);
            await SendAsync($"JOIN_ROOM:{roomName}");
        }

        public async Task LeaveRoomAsync(string roomName)
        {
            if (string.IsNullOrWhiteSpace(roomName) || !_joinedRooms.Contains(roomName))
            {
                return;
            }

            _joinedRooms.Remove(roomName);
            await SendAsync($"LEAVE_ROOM:{roomName}");
        }

        public async Task SendToRoomAsync(string roomName, string message)
        {
            if (string.IsNullOrWhiteSpace(roomName) || !_joinedRooms.Contains(roomName))
            {
                return;
            }

            await SendAsync($"ROOM_MSG:{roomName}:{message}");
        }

        public IReadOnlyCollection<string> GetJoinedRooms()
        {
            return _joinedRooms.ToList().AsReadOnly();
        }

        public async Task SendAsync(string message) => await SendAsync(Encoding.UTF8.GetBytes(message));
        private async Task SendNicknameAsync(string nickname) => await SendAsync($"NICKNAME:{nickname}");

        private async Task AutoReconnectAsync()
        {
            if (!_config.EnableAutoReconnect || IsAutoReconnecting)
            {
                return;
            }

            int attempt = 0;
            IsAutoReconnecting = true;

            while (!IsConnected && (_config.MaxReconnectAttempts == 0 || attempt < _config.MaxReconnectAttempts))
            {
                attempt++;
                try
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Reconnecting attempt {attempt}" });
                    await ConnectAsync();
                    if (IsConnected)
                    {
                        OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Reconnected after {attempt} attempt(s)" });
                        break;
                    }
                }
                catch { }

                await Task.Delay(_config.ReconnectDelayMs);
            }

            if (!IsConnected)
            {
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = "Failed to reconnect" });
            }

            IsAutoReconnecting = false;
        }

        private string _nickname;
        public async Task SetNicknameAsync(string nickname)
        {
            _nickname = nickname;
            await SendNicknameAsync(nickname);
        }

        public string Nickname => _nickname;


        public async Task DisconnectAsync()
        {
            lock (_stateLock)
            {
                if (!IsConnected)
                {
                    return;
                }

                IsConnected = false;
                _cancellation?.Cancel();
            }

            _tcpClient?.Close();
            _udpClient?.Close();
            _stream?.Dispose();
            _aesEncryption?.Dispose();
            _joinedRooms?.Clear();
            
            OnDisconnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self" });
        }

        public void Dispose()
        {
            _cancellation?.Cancel();
            DisconnectAsync().Wait();
            _cancellation?.Dispose();
            _sendLock.Dispose();
        }
    }
}
