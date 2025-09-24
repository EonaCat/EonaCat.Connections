using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EonaCat.Connections
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.
    public enum DisconnectReason
    {
        Unknown,
        RemoteClosed,
        LocalClosed,
        Timeout,
        Error,
        ServerShutdown,
        Reconnect,
        ClientRequested,
        Forced
    }
}
