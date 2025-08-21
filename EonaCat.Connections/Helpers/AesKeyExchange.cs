using System.Security.Cryptography;
using System.Text;

namespace EonaCat.Connections.Helpers
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public static class AesKeyExchange
    {
        private static readonly string Pepper = "EonaCat.Connections.Salt";

        /// <summary>
        /// Send AES key, IV, and salt to the stream.
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="aes"></param>
        /// <returns></returns>
        public static async Task<Aes> SendAesKeyAsync(Stream stream, Aes aes, string password = null)
        {
            var rawKey = aes.Key;
            var iv = aes.IV;
            var salt = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Send raw key, IV, and salt
            await WriteBytesWithLengthAsync(stream, rawKey);
            await WriteBytesWithLengthAsync(stream, iv);
            await WriteBytesWithLengthAsync(stream, salt);
            await stream.FlushAsync();

            // Derive key using PBKDF2-SHA256 + salt + password + pepper
            if (string.IsNullOrEmpty(password))
            {
                password = "EonaCat.Connections";
            }
            var derivedKey = PBKDF2_SHA256(Combine(Combine(rawKey, Encoding.UTF8.GetBytes(password)), Encoding.UTF8.GetBytes(Pepper)), salt, 100_000, 32);
            aes.Key = derivedKey;

            return aes;
        }

        /// <summary>
        /// Receive AES key, IV, and salt from the stream and derive the AES key.
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static async Task<Aes> ReceiveAesKeyAsync(Stream stream, string password = null)
        {
            var rawKey = await ReadBytesWithLengthAsync(stream);
            var iv = await ReadBytesWithLengthAsync(stream);
            var salt = await ReadBytesWithLengthAsync(stream);

            if (string.IsNullOrEmpty(password))
            {
                password = "EonaCat.Connections";
            }

            // Derived key using PBKDF2-SHA256 + salt + password + pepper
            var derivedKey = PBKDF2_SHA256(Combine(Combine(rawKey, Encoding.UTF8.GetBytes(password)), Encoding.UTF8.GetBytes(Pepper)), salt, 100_000, 32);

            Aes _aesEncryption = Aes.Create();
            _aesEncryption.Key = derivedKey;
            _aesEncryption.IV = iv;
            return _aesEncryption;
        }

        private static byte[] PBKDF2_SHA256(byte[] password, byte[] salt, int iterations, int outputBytes)
        {
            using (var hmac = new HMACSHA256(password))
            {
                int hashLength = hmac.HashSize / 8;
                int keyBlocks = (int)Math.Ceiling((double)outputBytes / hashLength);
                byte[] output = new byte[outputBytes];
                byte[] buffer = new byte[hashLength];

                for (int block = 1; block <= keyBlocks; block++)
                {
                    byte[] intBlock = BitConverter.GetBytes(block);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(intBlock);
                    }

                    hmac.Initialize();
                    hmac.TransformBlock(salt, 0, salt.Length, salt, 0);
                    hmac.TransformFinalBlock(intBlock, 0, intBlock.Length);
                    Array.Copy(hmac.Hash, buffer, hashLength);

                    byte[] temp = (byte[])buffer.Clone();
                    for (int i = 1; i < iterations; i++)
                    {
                        temp = hmac.ComputeHash(temp);
                        for (int j = 0; j < hashLength; j++)
                        {
                            buffer[j] ^= temp[j];
                        }
                    }

                    int offset = (block - 1) * hashLength;
                    int remaining = Math.Min(hashLength, outputBytes - offset);
                    Array.Copy(buffer, 0, output, offset, remaining);
                }

                return output;
            }
        }

        private static async Task<byte[]> ReadBytesWithLengthAsync(Stream stream)
        {
            var lengthBytes = new byte[4];
            await ReadExactlyAsync(stream, lengthBytes, 0, 4);
            int length = BitConverter.ToInt32(lengthBytes, 0);

            var data = new byte[length];
            await ReadExactlyAsync(stream, data, 0, length);
            return data;
        }

        private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, int offset, int count)
        {
            int totalRead = 0;
            while (totalRead < count)
            {
                int read = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead);
                if (read == 0)
                {
                    throw new EndOfStreamException("Stream ended prematurely");
                }

                totalRead += read;
            }
        }

        private static async Task WriteBytesWithLengthAsync(Stream stream, byte[] data)
        {
            var lengthBytes = BitConverter.GetBytes(data.Length);
            await stream.WriteAsync(lengthBytes, 0, 4);
            await stream.WriteAsync(data, 0, data.Length);
        }

        private static byte[] Combine(byte[] a, byte[] b)
        {
            var c = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, c, 0, a.Length);
            Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
            return c;
        }
    }
}