using System.Net;

namespace EonaCat.Connections.EventArguments
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class ConnectionEventArgs : EventArgs
    {
        public string ClientId { get; set; }
        public string Nickname { get; set; }
        public bool HasNickname => !string.IsNullOrEmpty(Nickname);
        public IPEndPoint RemoteEndPoint { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}