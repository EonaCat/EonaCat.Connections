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

    /// <summary>
    /// Processes incoming data streams into JSON or text messages per client buffer.
    /// </summary>
    public class JsonDataProcessor<TMessage> : IDisposable
    {
        private const int DefaultMaxBufferSize = 20 * 1024 * 1024; // 20 MB
        private const int DefaultMaxMessagesPerBatch = 200;
        private static readonly TimeSpan DefaultClientBufferTimeout = TimeSpan.FromMinutes(5);

        private readonly ConcurrentDictionary<string, BufferEntry> _buffers = new ConcurrentDictionary<string, BufferEntry>();
        private readonly Timer _cleanupTimer;
        private bool _isDisposed;

        /// <summary>
        /// Maximum allowed buffer size in bytes (default: 20 MB).
        /// </summary>
        public int MaxAllowedBufferSize { get; set; } = DefaultMaxBufferSize;

        /// <summary>
        /// Maximum number of messages processed per batch (default: 200).
        /// </summary>
        public int MaxMessagesPerBatch { get; set; } = DefaultMaxMessagesPerBatch;

        /// <summary>
        /// Default client name when one is not provided in <see cref="DataReceivedEventArgs"/>.
        /// </summary>
        public string ClientName { get; set; } = Guid.NewGuid().ToString();

        public Action<TMessage, string, string> ProcessMessage { get; set; }
        public Action<string, string> ProcessTextMessage { get; set; }

        public event EventHandler<Exception> OnMessageError;
        public event EventHandler<Exception> OnError;

        private class BufferEntry
        {
            public readonly StringBuilder Buffer = new StringBuilder();
            public DateTime LastUsed = DateTime.UtcNow;
            public readonly object SyncRoot = new object();
        }

        public JsonDataProcessor()
        {
            _cleanupTimer = new Timer(DefaultClientBufferTimeout.TotalMilliseconds / 5);
            _cleanupTimer.AutoReset = true;
            _cleanupTimer.Elapsed += CleanupInactiveClients;
            _cleanupTimer.Start();
        }

        /// <summary>
        /// Process incoming raw data.
        /// </summary>
        public void Process(DataReceivedEventArgs e)
        {
            EnsureNotDisposed();

            if (e.IsBinary)
            {
                e.StringData = Encoding.UTF8.GetString(e.Data);
            }

            if (string.IsNullOrWhiteSpace(e.StringData))
            {
                OnError?.Invoke(this, new Exception("Received empty data."));
                return;
            }

            string clientName = string.IsNullOrWhiteSpace(e.Nickname) ? ClientName : e.Nickname;
            string incomingText = e.StringData.Trim();
            if (incomingText.Length == 0)
            {
                return;
            }

            var bufferEntry = _buffers.GetOrAdd(clientName, _ => new BufferEntry());

            lock (bufferEntry.SyncRoot)
            {
                if (bufferEntry.Buffer.Length > MaxAllowedBufferSize)
                {
                    bufferEntry.Buffer.Clear();
                }

                bufferEntry.Buffer.Append(incomingText);
                bufferEntry.LastUsed = DateTime.UtcNow;

                int processedCount = 0;

                while (processedCount < MaxMessagesPerBatch &&
                       ExtractNextJson(bufferEntry.Buffer, out var jsonChunk))
                {
                    ProcessDataReceived(jsonChunk, clientName);
                    processedCount++;
                }

                // Handle leftover non-JSON text
                if (bufferEntry.Buffer.Length > 0 && !ContainsJsonStructure(bufferEntry.Buffer))
                {
                    var leftover = bufferEntry.Buffer.ToString();
                    bufferEntry.Buffer.Clear();
                    ProcessTextMessage?.Invoke(leftover, clientName);
                }
            }
        }

        private void ProcessDataReceived(string data, string clientName)
        {
            EnsureNotDisposed();

            if (string.IsNullOrWhiteSpace(data))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(clientName))
            {
                clientName = ClientName;
            }

            bool looksLikeJson = data.Length > 1 &&
                                 ((data[0] == '{' && data[data.Length - 1] == '}') ||
                                  (data[0] == '[' && data[data.Length - 1] == ']') ||
                                  data[0] == '"' || // string
                                  char.IsDigit(data[0]) || data[0] == '-' || // numbers
                                  data.StartsWith("true") ||
                                  data.StartsWith("false") ||
                                  data.StartsWith("null"));

            if (!looksLikeJson)
            {
                ProcessTextMessage?.Invoke(data, clientName);
                return;
            }

            try
            {
                // Try to detect JSON-encoded exceptions
                if (data.IndexOf("Exception", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    data.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    TryHandleJsonException(data);
                }

                var messages = JsonHelper.ToObjects<TMessage>(data);
                if (messages != null && ProcessMessage != null)
                {
                    foreach (var message in messages)
                    {
                        ProcessMessage(message, clientName, data);
                    }
                }
            }
            catch (Exception ex)
            {
                OnError?.Invoke(this, new Exception("Failed to process JSON message.", ex));
            }
        }

        private void TryHandleJsonException(string data)
        {
            try
            {
                var jsonObject = JObject.Parse(data);
                var exceptionToken = jsonObject.SelectToken("Exception");
                if (exceptionToken != null && exceptionToken.Type != JTokenType.Null)
                {
                    var exception = JsonHelper.ExtractException(data);
                    if (exception != null && OnMessageError != null)
                    {
                        OnMessageError(this, new Exception(exception.Message));
                    }
                }
            }
            catch
            {
                // Ignore malformed exception JSON
            }
        }

        private static bool ExtractNextJson(StringBuilder buffer, out string json)
        {
            json = null;
            if (buffer.Length == 0)
            {
                return false;
            }

            int depth = 0;
            bool inString = false, escape = false;
            int startIndex = -1;

            for (int i = 0; i < buffer.Length; i++)
            {
                char c = buffer[i];

                if (inString)
                {
                    if (escape)
                    {
                        escape = false;
                    }
                    else if (c == '\\')
                    {
                        escape = true;
                    }
                    else if (c == '"')
                    {
                        inString = false;
                    }
                }
                else
                {
                    switch (c)
                    {
                        case '"':
                            inString = true;
                            if (depth == 0 && startIndex == -1)
                            {
                                startIndex = i; // string-only JSON
                            }

                            break;

                        case '{':
                        case '[':
                            if (depth == 0)
                            {
                                startIndex = i;
                            }

                            depth++;
                            break;

                        case '}':
                        case ']':
                            depth--;
                            if (depth == 0 && startIndex != -1)
                            {
                                int length = i - startIndex + 1;
                                json = buffer.ToString(startIndex, length);
                                buffer.Remove(0, i + 1);
                                return true;
                            }
                            break;

                        default:
                            if (depth == 0 && startIndex == -1 &&
                                (char.IsDigit(c) || c == '-' || c == 't' || c == 'f' || c == 'n'))
                            {
                                startIndex = i;
                                int tokenEnd = FindPrimitiveEnd(buffer, i);
                                json = buffer.ToString(startIndex, tokenEnd - startIndex);
                                buffer.Remove(0, tokenEnd);
                                return true;
                            }
                            break;
                    }
                }
            }

            return false;
        }

        private static int FindPrimitiveEnd(StringBuilder buffer, int startIndex)
        {
            // Keywords: true/false/null
            if (buffer.Length >= startIndex + 4 && buffer.ToString(startIndex, 4) == "true")
            {
                return startIndex + 4;
            }

            if (buffer.Length >= startIndex + 5 && buffer.ToString(startIndex, 5) == "false")
            {
                return startIndex + 5;
            }

            if (buffer.Length >= startIndex + 4 && buffer.ToString(startIndex, 4) == "null")
            {
                return startIndex + 4;
            }

            // Numbers: scan until non-number/decimal/exponent
            int i = startIndex;
            while (i < buffer.Length)
            {
                char c = buffer[i];
                if (!(char.IsDigit(c) || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E'))
                {
                    break;
                }

                i++;
            }
            return i;
        }

        private static bool ContainsJsonStructure(StringBuilder buffer)
        {
            for (int i = 0; i < buffer.Length; i++)
            {
                char c = buffer[i];
                if (c == '{' || c == '[' || c == '"' || c == 't' || c == 'f' || c == 'n' || c == '-' || char.IsDigit(c))
                {
                    return true;
                }
            }
            return false;
        }

        private void CleanupInactiveClients(object sender, ElapsedEventArgs e)
        {
            var now = DateTime.UtcNow;

            foreach (var kvp in _buffers)
            {
                var bufferEntry = kvp.Value;
                if (now - bufferEntry.LastUsed > DefaultClientBufferTimeout)
                {
                    BufferEntry removed;
                    if (_buffers.TryRemove(kvp.Key, out removed))
                    {
                        lock (removed.SyncRoot)
                        {
                            removed.Buffer.Clear();
                        }
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

            BufferEntry removed;
            if (_buffers.TryRemove(clientName, out removed))
            {
                lock (removed.SyncRoot)
                {
                    removed.Buffer.Clear();
                }
            }
        }

        private void EnsureNotDisposed()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(nameof(JsonDataProcessor<TMessage>));
            }
        }

        public void Dispose()
        {
            if (_isDisposed)
            {
                return;
            }

            try
            {
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
            finally
            {
                _isDisposed = true;
            }
        }
    }
}
