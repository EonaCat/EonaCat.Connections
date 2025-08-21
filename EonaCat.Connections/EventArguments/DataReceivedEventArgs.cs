using System.Net;

namespace EonaCat.Connections
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class DataReceivedEventArgs : EventArgs
    {
        public string ClientId { get; internal set; }
        public byte[] Data { get; internal set; }
        public string StringData { get; internal set; }
        public bool IsBinary { get; internal set; }
        public DateTime Timestamp { get; internal set; } = DateTime.UtcNow;
        public IPEndPoint RemoteEndPoint { get; internal set; }
        public string Nickname { get; internal set; }
        public bool HasNickname => !string.IsNullOrEmpty(Nickname);
    }
}