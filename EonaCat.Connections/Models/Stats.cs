namespace EonaCat.Connections
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public class Stats
    {
        public int ActiveConnections { get; set; }
        public long TotalConnections { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public long MessagesSent { get; set; }
        public long MessagesReceived { get; set; }
        public DateTime StartTime { get; set; }
        public TimeSpan Uptime => DateTime.UtcNow - StartTime;
        public double MessagesPerSecond => MessagesReceived / Math.Max(1, Uptime.TotalSeconds);
    }
}