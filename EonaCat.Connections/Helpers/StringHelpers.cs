namespace EonaCat.Connections.Helpers
{
    internal class StringHelper
    {
        // This file is part of the EonaCat project(s) which is released under the Apache License.
        // See the LICENSE file or go to https://EonaCat.com/license for full license details.

        public static string GetTextBetweenTags(string message, string startTag, string endTag)
        {
            int startIndex = message.IndexOf(startTag);
            if (startIndex == -1)
            {
                return string.Empty;
            }

            int endIndex = message.IndexOf(endTag, startIndex + startTag.Length);
            if (endIndex == -1)
            {
                return string.Empty;
            }

            int length = endIndex - startIndex - startTag.Length;
            if (length < 0)
            {
                return string.Empty;
            }

            return message.Substring(startIndex + startTag.Length, length);
        }
    }
}
