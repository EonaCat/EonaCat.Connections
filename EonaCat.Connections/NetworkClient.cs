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

    public class NetworkClient
    {
        private readonly Configuration _config;
        private TcpClient _tcpClient;
        private UdpClient _udpClient;
        private Stream _stream;
        private Aes _aesEncryption;
        private CancellationTokenSource _cancellation;
        private bool _isConnected;

        public event EventHandler<ConnectionEventArgs> OnConnected;
        public event EventHandler<DataReceivedEventArgs> OnDataReceived;
        public event EventHandler<ConnectionEventArgs> OnDisconnected;
        public event EventHandler<ErrorEventArgs> OnSslError;
        public event EventHandler<ErrorEventArgs> OnEncryptionError;
        public event EventHandler<ErrorEventArgs> OnGeneralError;

        public NetworkClient(Configuration config)
        {
            _config = config;
        }

        public async Task ConnectAsync()
        {
            _cancellation = new CancellationTokenSource();

            if (_config.Protocol == ProtocolType.TCP)
            {
                await ConnectTcpAsync();
            }
            else
            {
                await ConnectUdp();
            }
        }

        private async Task ConnectTcpAsync()
        {
            try
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

                OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });

                // Start receiving data
                _ = Task.Run(() => ReceiveDataAsync(), _cancellation.Token);
            }
            catch (Exception ex)
            {
                OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Failed to connect" });
            }
        }

        public string IpAddress => _config != null ? _config.Host : string.Empty;
        public int Port => _config != null ? _config.Port : 0;
        private async Task ConnectUdp()
        {
            await Task.Run(() =>
            {
                try
                {
                    _udpClient = new UdpClient();
                    _udpClient.Connect(_config.Host, _config.Port);
                    _isConnected = true;

                    OnConnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self", RemoteEndPoint = new IPEndPoint(IPAddress.Parse(_config.Host), _config.Port) });

                    // Start receiving data
                    _ = Task.Run(() => ReceiveUdpDataAsync(), _cancellation.Token);
                }
                catch (Exception ex)
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Failed to connect UDP" });
                }
            });
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
                        // Read 4-byte length prefix
                        var lengthBuffer = new byte[4];
                        int read = await ReadExactAsync(_stream, lengthBuffer, 4, _cancellation.Token);
                        if (read == 0)
                        {
                            break;
                        }

                        if (BitConverter.IsLittleEndian)
                        {
                            Array.Reverse(lengthBuffer);
                        }

                        int length = BitConverter.ToInt32(lengthBuffer, 0);

                        // Read encrypted payload
                        var encrypted = new byte[length];
                        await ReadExactAsync(_stream, encrypted, length, _cancellation.Token);
                        data = await DecryptDataAsync(encrypted, _aesEncryption);
                    }
                    else
                    {
                        data = new byte[_config.BufferSize];
                        int bytesRead = await _stream.ReadAsync(data, 0, data.Length, _cancellation.Token);
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
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error receiving data" });
                    _isConnected = false;

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
                    _isConnected = false;

                    // Start reconnect
                    _ = Task.Run(() => AutoReconnectAsync());
                    break;
                }
            }
        }

        private async Task ProcessReceivedDataAsync(byte[] data)
        {
            await Task.Run(() =>
            {
                try
                {
                    // Data is already decrypted if AES is enabled
                    // Just update stats / handle string conversion

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
                    if (_config.UseAesEncryption)
                    {
                        OnEncryptionError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error processing data" });
                    }
                    else
                    {
                        OnGeneralError?.Invoke(this, new ErrorEventArgs { Exception = ex, Message = "Error processing data" });
                    }
                }
            });
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
                    // Encrypt payload
                    data = await EncryptDataAsync(data, _aesEncryption);

                    // Prepend 4-byte length for framing
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
                }
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

        private async Task AutoReconnectAsync()
        {
            if (!_config.EnableAutoReconnect)
            {
                return;
            }

            int attempt = 0;

            while (!_isConnected && (_config.MaxReconnectAttempts == 0 || attempt < _config.MaxReconnectAttempts))
            {
                attempt++;
                try
                {
                    OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Attempting to reconnect (Attempt {attempt})" });
                    await ConnectAsync();

                    if (_isConnected)
                    {
                        OnGeneralError?.Invoke(this, new ErrorEventArgs { Message = $"Reconnected successfully after {attempt} attempt(s)" });
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


        public async Task DisconnectAsync()
        {
            await Task.Run(() =>
            {
                _isConnected = false;
                _cancellation?.Cancel();
                _tcpClient?.Close();
                _udpClient?.Close();
                _stream?.Dispose();
                _aesEncryption?.Dispose();

                OnDisconnected?.Invoke(this, new ConnectionEventArgs { ClientId = "self" });

                _ = Task.Run(() => AutoReconnectAsync());
            });
        }

        public void Dispose()
        {
            DisconnectAsync().Wait();
            _cancellation?.Dispose();
        }
    }
}