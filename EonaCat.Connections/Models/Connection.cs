using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace EonaCat.Connections.Models
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class Connection
    {
        public string Id { get; set; }
        public TcpClient TcpClient { get; set; }
        public UdpClient UdpClient { get; set; }
        public IPEndPoint RemoteEndPoint { get; set; }
        public Stream Stream { get; set; }

        private string _nickName;
        public string Nickname
        {
            get
            {
                if (string.IsNullOrWhiteSpace(_nickName))
                {
                    _nickName = Id;
                }
                return _nickName;
            }

            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    _nickName = Id;
                }
                else
                {
                    _nickName = value;
                }
            }
        }

        public bool HasNickname => !string.IsNullOrWhiteSpace(_nickName) && _nickName != Id;

        public DateTime ConnectedAt { get; set; }
        public DateTime LastActive { get; set; }
        public bool IsSecure { get; set; }
        public bool IsEncrypted { get; set; }
        public Aes AesEncryption { get; set; }
        public CancellationTokenSource CancellationToken { get; set; }
        private long _bytesReceived;
        private long _bytesSent;
        public long BytesReceived => Interlocked.Read(ref _bytesReceived);
        public long BytesSent => Interlocked.Read(ref _bytesSent);

        public void AddBytesReceived(long count) => Interlocked.Add(ref _bytesReceived, count);
        public void AddBytesSent(long count) => Interlocked.Add(ref _bytesSent, count);

        public SemaphoreSlim SendLock { get; } = new SemaphoreSlim(1, 1);
        public SemaphoreSlim ReadLock { get; } = new SemaphoreSlim(1, 1);

        private int _disconnected;
        public bool MarkDisconnected() => Interlocked.Exchange(ref _disconnected, 1) == 0;
    }
}