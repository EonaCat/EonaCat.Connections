using System.Net;
using System.Net.Sockets;

namespace EonaCat.Connections.EventArguments
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class ConnectionEventArgs : EventArgs
    {
        public string ClientId { get; set; }
        public string Nickname { get; set; }
        public IPEndPoint RemoteEndPoint { get; set; }
        public DisconnectReason Reason { get; set; } = DisconnectReason.Unknown;
        public Exception Exception { get; set; }
        public bool HasException => Exception != null;

        public bool IsLocalDisconnect =>
            Reason == DisconnectReason.LocalClosed
            || Reason == DisconnectReason.Timeout
            || Reason == DisconnectReason.ServerShutdown
            || Reason == DisconnectReason.Reconnect
            || Reason == DisconnectReason.ClientRequested
            || Reason == DisconnectReason.Forced;

        public bool IsRemoteDisconnect =>
            Reason == DisconnectReason.RemoteClosed;

        public bool HasNickname => !string.IsNullOrWhiteSpace(Nickname);
        public bool HasClientId => !string.IsNullOrWhiteSpace(ClientId);
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public bool HasRemoteEndPoint => RemoteEndPoint != null;
        public bool IsRemoteEndPointIPv4 => RemoteEndPoint?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
        public bool HasRemoteEndPointIPv6 => RemoteEndPoint?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        public bool IsRemoteEndPointLoopback => RemoteEndPoint != null && IPAddress.IsLoopback(RemoteEndPoint.Address);


        public static DisconnectReason Determine(DisconnectReason reason, Exception ex)
        {
            if (ex == null)
            {
                return reason;
            }

            if (ex is SocketException socketEx)
            {
                switch (socketEx.SocketErrorCode)
                {
                    case SocketError.ConnectionReset:
                    case SocketError.Shutdown:
                    case SocketError.Disconnecting:
                        return DisconnectReason.RemoteClosed;

                    case SocketError.TimedOut:
                        return DisconnectReason.Timeout;

                    case SocketError.NetworkDown:
                    case SocketError.NetworkReset:
                    case SocketError.NetworkUnreachable:
                        return DisconnectReason.Error;

                    default:
                        return DisconnectReason.Error;
                }
            }

            if (ex is ObjectDisposedException || ex is InvalidOperationException)
            {
                return DisconnectReason.LocalClosed;
            }

            if (ex.Message.Contains("An existing connection was forcibly closed by the remote host")
                || ex.Message.Contains("The remote party has closed the transport stream"))
            {
                return DisconnectReason.RemoteClosed;
            }

            return DisconnectReason.Error;
        }
    }
}