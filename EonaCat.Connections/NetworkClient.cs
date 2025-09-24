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
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class NetworkClient : IDisposable
    {
        private readonly Configuration _config;
        private TcpClient _tcpClient;
        private UdpClient _udpClient;
        private Stream _stream;
        private Aes _aesEncryption;
        private CancellationTokenSource _cancellation;
        private bool _isConnected;

        public bool IsConnected => _isConnected;
        public bool IsSecure => _config != null && (_config.UseSsl || _config.UseAesEncryption);
        public bool IsEncrypted => _config != null && _config.UseAesEncryption;
        public bool IsTcp => _config != null && _config.Protocol == ProtocolType.TCP;

        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private readonly SemaphoreSlim _connectLock = new(1, 1);
        private readonly SemaphoreSlim _readLock = new(1, 1);

        public DateTime ConnectionTime { get; private set; }
        public DateTime StartTime { get; set; }
        public TimeSpan Uptime => DateTime.UtcNow - ConnectionTime;

        private bool _disposed;
        public event EventHandler<ConnectionEventArgs> OnConnected;
        public event EventHandler<DataReceivedEventArgs> OnDataReceived;
        public event EventHandler<ConnectionEventArgs> OnDisconnected;
        public event EventHandler<ErrorEventArgs> OnSslError;
        public event EventHandler<ErrorEventArgs> OnEncryptionError;
        public event EventHandler<ErrorEventArgs> OnGeneralError;

        private readonly List<IClientPlugin> _plugins = new();

        public NetworkClient(Configuration config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
        }

        public async Task ConnectAsync()
        {
            await _connectLock.WaitAsync();
            try
            {
                _cancellation = new CancellationTokenSource();

                if (_config.Protocol == ProtocolType.TCP)
                {
                    await ConnectTcpAsync();
                }
                else
                {
                    await ConnectUdpAsync();
                }
            }
            catch (Exception ex)
            {
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Connection error" });
                NotifyError(ex, "General error");
                if (_config.EnableAutoReconnect)
                {
                    _ = Task.Run(() => AutoReconnectAsync());
                }
            }
            finally
            {
                _connectLock.Release();
            }
        }

        private async Task ConnectTcpAsync()
        {
            _tcpClient = new TcpClient();
            await _tcpClient.ConnectAsync(_config.Host, _config.Port);

            Stream stream = _tcpClient.GetStream();

            // Setup SSL if required
            if (_config.UseSsl)
            {
                try
                {
                    var sslStream = new SslStream(stream, false, userCertificateValidationCallback: _config.GetRemoteCertificateValidationCallback());
                    if (_config.Certificate != null)
                    {
                        await sslStream.AuthenticateAsClientAsync(
                            _config.Host,
                            new X509CertificateCollection { _config.Certificate },
                            _config.CheckCertificateRevocation
                        );
                    }
                    else
                    {
                        await sslStream.AuthenticateAsClientAsync(_config.Host);
                    }
                    stream = sslStream;
                }
                catch (Exception ex)
                {
                    OnSslError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "SSL authentication failed" });
                    return;
                }
            }

            // Setup AES encryption if required
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

            _stream = stream;
            _isConnected = true;
            ConnectionTime = DateTime.UtcNow;
            OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });
            NotifyConnected();

            // Start receiving data
            _ = Task.Run(() => ReceiveDataAsync(), _cancellation.Token);
        }

        public void RegisterPlugin(IClientPlugin plugin)
        {
            if (_plugins.Any(p => p.Name == plugin.Name))
                return;

            _plugins.Add(plugin);
            plugin.OnClientStarted(this);
        }

        public void UnregisterPlugin(IClientPlugin plugin)
        {
            if (_plugins.Remove(plugin))
            {
                plugin.OnClientStopped(this);
            }
        }

        private void NotifyConnected()
        {
            foreach (var plugin in _plugins)
            {
                plugin.OnClientConnected(this);
            }
        }

        private void NotifyDisconnected(DisconnectReason reason, Exception exception)
        {
            foreach (var plugin in _plugins)
            {
                plugin.OnClientDisconnected(this, reason, exception);
            }
        }

        private void NotifyData(byte[] data, string stringData, bool isBinary)
        {
            foreach (var plugin in _plugins)
            {
                plugin.OnDataReceived(this, data, stringData, isBinary);
            }
        }

        private void NotifyError(Exception ex, string message)
        {
            foreach (var plugin in _plugins)
            {
                plugin.OnError(this, ex, message);
            }
        }

        public string IpAddress => _config != null ? _config.Host : string.Empty;
        public int Port => _config != null ? _config.Port : 0;

        public bool IsAutoReconnectRunning { get; private set; }

        private async Task ConnectUdpAsync()
        {
            _udpClient = new UdpClient();
            _udpClient.Connect(_config.Host, _config.Port);
            _isConnected = true;
            ConnectionTime = DateTime.UtcNow;
            OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });

            // Start receiving data
            _ = Task.Run(() => ReceiveUdpDataAsync(), _cancellation.Token);
            await Task.CompletedTask;
        }

        private async Task ReceiveDataAsync()
        {
            while (!_cancellation.Token.IsCancellationRequested && _isConnected)
            {
                try
                {
                    byte[] data;

                    if (_config.UseAesEncryption && _aesEncryption != null)
                    {
                        var lengthBuffer = new byte[4];
                        int read = await ReadExactAsync(_stream, lengthBuffer, 4, _cancellation.Token).ConfigureAwait(false);
                        if (read == 0)
                        {
                            break;
                        }

                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(lengthBuffer);
                        }

                        int length = BitConverter.ToInt32(lengthBuffer, 0);
                        if (length <= 0)
                        {
                            throw new InvalidDataException("Invalid packet length");
                        }

                        var encrypted = new byte[length];
                        await ReadExactAsync(_stream, encrypted, length, _cancellation.Token).ConfigureAwait(false);
                        data = await AesKeyExchange.DecryptDataAsync(encrypted, _aesEncryption).ConfigureAwait(false);
                    }
                    else
                    {
                        data = new byte[_config.BufferSize];
                        int bytesRead;
                        await _readLock.WaitAsync(_cancellation.Token);
                        try
                        {
                            bytesRead = await _stream.ReadAsync(data, 0, data.Length, _cancellation.Token);
                        }
                        finally
                        {
                            _readLock.Release();
                        }

                        if (bytesRead == 0)
                        {
                            await DisconnectAsync(DisconnectReason.RemoteClosed);
                            return;
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
                catch (IOException ioEx)
                {
                    await DisconnectAsync(DisconnectReason.RemoteClosed, ioEx);
                }
                catch (SocketException sockEx)
                {
                    await DisconnectAsync(DisconnectReason.Error, sockEx);
                }
                catch (OperationCanceledException)
                {
                    await DisconnectAsync(DisconnectReason.Timeout);
                }
                catch (Exception ex)
                {
                    await DisconnectAsync(DisconnectReason.Error, ex);
                }
            }

            await DisconnectAsync();
        }

        private async Task<int> ReadExactAsync(Stream stream, byte[] buffer, int length, CancellationToken ct)
        {
            int offset = 0;
            await _readLock.WaitAsync(ct);
            try
            {
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
                _readLock.Release();
            }
        }

        private async Task ReceiveUdpDataAsync()
        {
            while (!_cancellation.Token.IsCancellationRequested && _isConnected)
            {
                try
                {
                    var result = await _udpClient.ReceiveAsync();
                    await ProcessReceivedDataAsync(result.Buffer);
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error receiving data" });
                    NotifyError(ex, "General error");
                    _isConnected = false;
                    ConnectionTime = DateTime.MinValue;
                    _ = Task.Run(() => AutoReconnectAsync());
                    break;
                }
            }
        }

        private async Task ProcessReceivedDataAsync(byte[] data)
        {
            try
            {
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
                catch
                {
                    // Keep as binary
                }

                if (!isBinary && stringData != null && stringData.Equals("DISCONNECT", StringComparison.OrdinalIgnoreCase))
                {
                    await DisconnectAsync(DisconnectReason.RemoteClosed);
                    return;
                }

                OnDataReceived?.Invoke(this, new DataReceivedEventArgs
                {
                    ClientId = "server",
                    Data = data,
                    StringData = stringData,
                    IsBinary = isBinary
                });
                NotifyData(data, stringData, isBinary);
            }
            catch (Exception ex)
            {
                if (_config.UseAesEncryption)
                {
                    OnEncryptionError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error processing data" });
                }
                else
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error processing data" });
                    NotifyError(ex, "General error");
                }
            }
        }

        public async Task SendAsync(byte[] data)
        {
            if (!_isConnected)
            {
                return;
            }

            await _sendLock.WaitAsync();
            try
            {
                if (_config.UseAesEncryption && _aesEncryption != null)
                {
                    data = await AesKeyExchange.EncryptDataAsync(data, _aesEncryption);

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
                if (_config.UseAesEncryption)
                {
                    OnEncryptionError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error encrypting/sending data" });
                }
                else
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error sending data" });
                    NotifyError(ex, "General error");
                }
            }
            finally
            {
                _sendLock.Release();
            }
        }

        public async Task SendAsync(string message)
        {
            await SendAsync(Encoding.UTF8.GetBytes(message));
        }

        public async Task SendNicknameAsync(string nickname)
        {
            await SendAsync($"NICKNAME:{nickname}");
        }

        private async Task AutoReconnectAsync()
        {
            if (!_config.EnableAutoReconnect)
            {
                return;
            }

            if (IsAutoReconnectRunning)
            {
                return;
            }

            int attempt = 0;

            while (_config.EnableAutoReconnect && !_isConnected && (_config.MaxReconnectAttempts == 0 || attempt < _config.MaxReconnectAttempts))
            {
                attempt++;

                try
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Attempting to reconnect (Attempt {attempt})" });
                    IsAutoReconnectRunning = true;
                    await ConnectAsync();

                    if (_isConnected)
                    {
                        OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Reconnected successfully after {attempt} attempt(s)" });
                        IsAutoReconnectRunning = false;
                        break;
                    }
                }
                catch
                {
                    // Do nothing
                }

                await Task.Delay(_config.ReconnectDelayMs);
            }

            if (!_isConnected)
            {
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = "Failed to reconnect" });
            }
        }

        public async Task DisconnectAsync(
    DisconnectReason reason = DisconnectReason.LocalClosed,
    Exception exception = null,
    bool forceDisconnection = false)
        {
            await _connectLock.WaitAsync();
            try
            {
                if (!_isConnected)
                {
                    return;
                }

                _isConnected = false;
                ConnectionTime = DateTime.MinValue;

                _cancellation?.Cancel();
                _tcpClient?.Close();
                _udpClient?.Close();
                _stream?.Dispose();
                _aesEncryption?.Dispose();

                OnDisconnected?.Invoke(this, new ConnectionEventArgs
                {
                    ClientId = "self",
                    RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port),
                    Reason = ConnectionEventArgs.Determine(reason, exception),
                    Exception = exception
                });
                NotifyDisconnected(reason, exception);

                if (!forceDisconnection && reason != DisconnectReason.Forced)
                {
                    _ = Task.Run(() => AutoReconnectAsync());
                }
                else
                {
                    Console.WriteLine("Auto-reconnect disabled due to forced disconnection.");
                    _config.EnableAutoReconnect = false;
                }
            }
            finally
            {
                _connectLock.Release();
            }
        }


        public async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            await DisconnectAsync(forceDisconnection: true);

            foreach (var plugin in _plugins.ToList())
            {
                plugin.OnClientStopped(this);
            }

            _cancellation?.Dispose();
            _sendLock.Dispose();
            _connectLock.Dispose();
            _readLock.Dispose();
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}
