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
            _cancellation?.Cancel();
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

        private async Task ConnectTcpAsync()
        {
            try
            {
                _tcpClient = new TcpClient();
                await _tcpClient.ConnectAsync(_config.Host, _config.Port);

                Stream stream = _tcpClient.GetStream();

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

                _stream = stream;
                _isConnected = true;

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });

                _ = Task.Run(() => ReceiveDataAsync(_cancellation.Token), _cancellation.Token);
            }
            catch (Exception ex)
            {
                _isConnected = false;
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Failed to connect" });
                _ = Task.Run(() => AutoReconnectAsync());
            }
        }

        private async Task ConnectUdpAsync()
        {
            try
            {
                _udpClient = new UdpClient();
                _udpClient.Connect(_config.Host, _config.Port);
                _isConnected = true;

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });

                _ = Task.Run(() => ReceiveUdpDataAsync(_cancellation.Token), _cancellation.Token);
            }
            catch (Exception ex)
            {
                _isConnected = false;
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Failed to connect UDP" });
            }
        }

        private async Task ReceiveDataAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested && _isConnected)
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
                    _isConnected = false;
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
            while (!ct.IsCancellationRequested && _isConnected)
            {
                try
                {
                    var result = await _udpClient.ReceiveAsync();
                    await ProcessReceivedDataAsync(result.Buffer);
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error receiving UDP data" });
                    _isConnected = false;
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
            if (!_isConnected)
            {
                return;
            }

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
        }

        public async Task SendAsync(string message) => await SendAsync(Encoding.UTF8.GetBytes(message));
        public async Task SendNicknameAsync(string nickname) => await SendAsync($"NICKNAME:{nickname}");

        private async Task AutoReconnectAsync()
        {
            if (!_config.EnableAutoReconnect || IsAutoReconnecting)
            {
                return;
            }

            int attempt = 0;

            while (!_isConnected && (_config.MaxReconnectAttempts == 0 || attempt < _config.MaxReconnectAttempts))
            {
                attempt++;
                try
                {
                    IsAutoReconnecting = true;
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Reconnecting attempt {attempt}" });
                    await ConnectAsync();
                    if (_isConnected)
                    {
                        IsAutoReconnecting = false;
                        OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Reconnected after {attempt} attempt(s)" });
                        break;
                    }
                }
                catch { }

                await Task.Delay(_config.ReconnectDelayMs);
            }

            if (!_isConnected)
            {
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = "Failed to reconnect" });
            }
        }

        public async Task DisconnectAsync()
        {
            _isConnected = false;
            _cancellation?.Cancel();

            _tcpClient?.Close();
            _udpClient?.Close();
            _stream?.Dispose();
            _aesEncryption?.Dispose();

            OnDisconnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self" });
        }

        public void Dispose()
        {
            _cancellation?.Cancel();
            DisconnectAsync().Wait();
            _cancellation?.Dispose();
        }
    }
}
