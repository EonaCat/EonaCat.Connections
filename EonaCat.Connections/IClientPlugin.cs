namespace EonaCat.Connections
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public interface IClientPlugin
    {
        string Name { get; }

        void OnClientStarted(NetworkClient client);
        void OnClientConnected(NetworkClient client);
        void OnClientDisconnected(NetworkClient client, DisconnectReason reason, Exception exception);
        void OnDataReceived(NetworkClient client, byte[] data, string stringData, bool isBinary);
        void OnError(NetworkClient client, Exception exception, string message);
        void OnClientStopped(NetworkClient client);
    }
}
