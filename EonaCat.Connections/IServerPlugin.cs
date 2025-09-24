using EonaCat.Connections.Models;

namespace EonaCat.Connections
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    /// <summary>
    /// Defines the contract for plugins that extend the behavior of the NetworkServer.
    /// Implement this interface to hook into server events such as
    /// client connections, disconnections, message handling, and lifecycle events.
    /// </summary>
    public interface IServerPlugin
    {
        /// <summary>
        /// Gets the unique name of this plugin (used for logging/error reporting).
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Called when the server has started successfully.
        /// </summary>
        /// <param name="server">The server instance that started.</param>
        void OnServerStarted(NetworkServer server);

        /// <summary>
        /// Called when the server has stopped.
        /// </summary>
        /// <param name="server">The server instance that stopped.</param>
        void OnServerStopped(NetworkServer server);

        /// <summary>
        /// Called when a client successfully connects.
        /// </summary>
        /// <param name="client">The connected client.</param>
        void OnClientConnected(Connection client);

        /// <summary>
        /// Called when a client disconnects.
        /// </summary>
        /// <param name="client">The client that disconnected.</param>
        /// <param name="reason">The reason for disconnection.</param>
        /// <param name="exception">Optional exception if the disconnect was caused by an error.</param>
        void OnClientDisconnected(Connection client, DisconnectReason reason, Exception exception);

        /// <summary>
        /// Called when data is received from a client.
        /// </summary>
        /// <param name="client">The client that sent the data.</param>
        /// <param name="data">The raw bytes received.</param>
        /// <param name="stringData">The decoded string (if text-based, otherwise null).</param>
        /// <param name="isBinary">True if the message is binary data, false if text.</param>
        void OnDataReceived(Connection client, byte[] data, string stringData, bool isBinary);
    }
}
