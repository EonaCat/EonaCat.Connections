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

        public DateTime ConnectedAt { get; set; }
        public DateTime LastActive { get; set; }
        public bool IsSecure { get; set; }
        public bool IsEncrypted { get; set; }
        public Aes AesEncryption { get; set; }
        public CancellationTokenSource CancellationToken { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
    }
}