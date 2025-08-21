using EonaCat.Json;
using EonaCat.Json.Linq;
using System.Collections.Concurrent;
using System.Text;
using System.Timers;
using Timer = System.Timers.Timer;

namespace EonaCat.Connections.Processors
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class JsonDataProcessor<TMessage> : IDisposable
    {
        public int MaxAllowedBufferSize = 20 * 1024 * 1024;
        public int MaxMessagesPerBatch = 200;
        private readonly ConcurrentDictionary<string, BufferEntry> _buffers = new();
        private readonly Timer _cleanupTimer;
        private readonly TimeSpan _clientBufferTimeout = TimeSpan.FromMinutes(5);
        private bool _isDisposed;

        /// <summary>
        /// This clientName will be used for the buffer (if not set in the DataReceivedEventArgs).
        /// </summary>
        public string ClientName { get; set; } = Guid.NewGuid().ToString();

        private class BufferEntry
        {
            public readonly StringBuilder Buffer = new();
            public DateTime LastUsed = DateTime.UtcNow;
            public readonly object SyncRoot = new();
        }

        public Action<TMessage, string, string>? ProcessMessage;
        public Action<string, string>? ProcessTextMessage;

        public event EventHandler<Exception>? OnMessageError;
        public event EventHandler<Exception>? OnError;

        public JsonDataProcessor()
        {
            _cleanupTimer = new Timer(_clientBufferTimeout.TotalMilliseconds / 5);
            _cleanupTimer.Elapsed += CleanupInactiveClients;
            _cleanupTimer.AutoReset = true;
            _cleanupTimer.Start();
        }

        public void Process(DataReceivedEventArgs e)
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(JsonDataProcessor<TMessage>));
            }

            if (e.IsBinary)
            {
                e.StringData = Encoding.UTF8.GetString(e.Data);
            }

            if (string.IsNullOrEmpty(e.StringData))
            {
                OnError?.Invoke(this, new Exception("Received empty data."));
                return;
            }

            string clientName = !string.IsNullOrWhiteSpace(e.Nickname) ? e.Nickname : ClientName;
            string incomingText = e.StringData.Trim();
            if (incomingText.Length == 0)
            {
                return;
            }

            var bufferEntry = _buffers.GetOrAdd(clientName, _ => new BufferEntry());
            List<string>? jsonChunksToProcess = null;
            string? textMessageToProcess = null;

            lock (bufferEntry.SyncRoot)
            {
                // Prevent growth before appending
                if (bufferEntry.Buffer.Length > MaxAllowedBufferSize)
                {
                    bufferEntry.Buffer.Clear();
                }

                bufferEntry.Buffer.Append(incomingText);
                bufferEntry.LastUsed = DateTime.UtcNow;

                int processedCount = 0;

                while (processedCount < MaxMessagesPerBatch && ExtractNextJson(bufferEntry.Buffer, out var jsonChunk))
                {
                    ProcessDataReceived(jsonChunk, clientName);
                    processedCount++;
                }

                if (bufferEntry.Buffer.Length > 0 && !ContainsJsonStructure(bufferEntry.Buffer))
                {
                    var leftover = bufferEntry.Buffer.ToString();
                    bufferEntry.Buffer.Clear();
                    ProcessTextMessage?.Invoke(leftover, clientName);
                }
            }

            if (textMessageToProcess != null)
            {
                ProcessTextMessage?.Invoke(textMessageToProcess, clientName);
            }

            if (jsonChunksToProcess != null)
            {
                foreach (var jsonChunk in jsonChunksToProcess)
                {
                    ProcessDataReceived(jsonChunk, clientName);
                }
            }
        }

        private void ProcessDataReceived(string? data, string clientName)
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(JsonDataProcessor<TMessage>));
            }

            if (data == null)
            {
                return;
            }

            if (string.IsNullOrEmpty(clientName))
            {
                clientName = ClientName;
            }

            if (string.IsNullOrWhiteSpace(data) || data.Length == 0)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(data))
            {
                return;
            }

            bool looksLikeJson = data.Length > 1 &&
                ((data[0] == '{' && data[data.Length - 1] == '}') || (data[0] == '[' && data[data.Length - 1] == ']'));

            if (!looksLikeJson)
            {
                ProcessTextMessage?.Invoke(data, clientName);
                return;
            }

            try
            {
                if (data.Contains("Exception") || data.Contains("Error"))
                {
                    try
                    {
                        var jsonObject = JObject.Parse(data);
                        var exceptionToken = jsonObject.SelectToken("Exception");
                        if (exceptionToken is { Type: not JTokenType.Null })
                        {
                            var exception = JsonHelper.ExtractException(data);
                            if (exception != null)
                            {
                                var currentException = new Exception(exception.Message);
                                OnMessageError?.Invoke(this, currentException);
                            }
                        }
                    }
                    catch (Exception)
                    {
                        // Do nothing
                    }
                }

                var messages = JsonHelper.ToObjects<TMessage>(data);
                if (messages != null)
                {
                    foreach (var message in messages)
                    {
                        ProcessMessage?.Invoke(message, clientName, data);
                    }
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(this, new Exception("Failed to process JSON message.", ex));
            }
        }


        private static bool ExtractNextJson(StringBuilder buffer, out string? json)
        {
            json = null;
            if (buffer.Length == 0)
            {
                return false;
            }

            int depth = 0;
            bool inString = false;
            bool escape = false;
            int startIndex = -1;

            for (int i = 0; i < buffer.Length; i++)
            {
                char currentCharacter = buffer[i];

                if (inString)
                {
                    if (escape)
                    {
                        escape = false;
                    }
                    else if (currentCharacter == '\\')
                    {
                        escape = true;
                    }
                    else if (currentCharacter == '"')
                    {
                        inString = false;
                    }
                }
                else
                {
                    if (currentCharacter == '"')
                    {
                        inString = true;
                        if (depth == 0 && startIndex == -1)
                        {
                            startIndex = i; // string-only JSON
                        }
                    }
                    else if (currentCharacter == '{' || currentCharacter == '[')
                    {
                        if (depth == 0)
                        {
                            startIndex = i;
                        }

                        depth++;
                    }
                    else if (currentCharacter == '}' || currentCharacter == ']')
                    {
                        depth--;
                        if (depth == 0 && startIndex != -1)
                        {
                            json = buffer.ToString(startIndex, i - startIndex + 1);
                            buffer.Remove(0, i + 1);
                            return true;
                        }
                    }
                    else if (depth == 0 && startIndex == -1 &&
                             (char.IsDigit(currentCharacter) || currentCharacter == '-' || currentCharacter == 't' || currentCharacter == 'f' || currentCharacter == 'n'))
                    {
                        startIndex = i;

                        // Find token end
                        int tokenEnd = FindPrimitiveEnd(buffer, i);
                        json = buffer.ToString(startIndex, tokenEnd - startIndex);
                        buffer.Remove(0, tokenEnd);
                        return true;
                    }
                }
            }
            return false;
        }

        private static int FindPrimitiveEnd(StringBuilder buffer, int startIndex)
        {
            for (int i = startIndex; i < buffer.Length; i++)
            {
                char c = buffer[i];
                if (char.IsWhiteSpace(c) || c == ',' || c == ']' || c == '}')
                {
                    return i;
                }
            }
            return buffer.Length;
        }

        private static bool ContainsJsonStructure(StringBuilder buffer)
        {
            for (int i = 0; i < buffer.Length; i++)
            {
                char c = buffer[i];
                if (c == '{' || c == '[' || c == '"' ||
                    c == 't' || c == 'f' || c == 'n' ||
                    c == '-' || char.IsDigit(c))
                {
                    return true;
                }
            }
            return false;
        }

        private void CleanupInactiveClients(object? sender, ElapsedEventArgs e)
        {
            var now = DateTime.UtcNow;

            foreach (var kvp in _buffers)
            {
                var bufferEntry = kvp.Value;
                if (now - bufferEntry.LastUsed > _clientBufferTimeout && _buffers.TryRemove(kvp.Key, out var removed))
                {
                    lock (removed.SyncRoot)
                    {
                        removed.Buffer.Clear();
                    }
                }
            }
        }

        public void RemoveClient(string clientName)
        {
            if (string.IsNullOrWhiteSpace(clientName))
            {
                return;
            }

            if (_buffers.TryRemove(clientName, out var removed))
            {
                lock (removed.SyncRoot)
                {
                    removed.Buffer.Clear();
                }
            }
        }

        public void Dispose()
        {
            if (_isDisposed)
            {
                return;
            }

            _isDisposed = true;

            _cleanupTimer.Stop();
            _cleanupTimer.Elapsed -= CleanupInactiveClients;
            _cleanupTimer.Dispose();

            foreach (var bufferEntry in _buffers.Values)
            {
                lock (bufferEntry.SyncRoot)
                {
                    bufferEntry.Buffer.Clear();
                }
            }
            _buffers.Clear();

            ProcessMessage = null;
            ProcessTextMessage = null;
            OnMessageError = null;
            OnError = null;
        }
    }
}
