using System.Security.Cryptography;

namespace EonaCat.Connections.Helpers
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public static class AesKeyExchange
    {
        private const int _saltSize = 16;
        private const int _keySize = 32;
        private const int _ivSize = 16;
        private const int _hmacSize = 32;
        private const int _pbkdf2Iterations = 100_000;

        // Returns an AES object derived from the password and salt
        public static async Task<Aes> ReceiveAesKeyAsync(Stream stream, string password)
        {
            // Read salt
            byte[] salt = new byte[_saltSize];
            await stream.ReadExactlyAsync(salt, 0, _saltSize);

            // Derive key
            byte[] key;
            using (var kdf = new Rfc2898DeriveBytes(password, salt, _pbkdf2Iterations, HashAlgorithmName.SHA256))
            {
                key = kdf.GetBytes(_keySize);
            }

            var aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;

            return aes;
        }

        // Sends salt (no key) to the other side
        public static async Task SendAesKeyAsync(Stream stream, Aes aes, string password)
        {
            // Generate random salt
            byte[] salt = new byte[_saltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // Derive AES key
            byte[] key;
            using (var kdf = new Rfc2898DeriveBytes(password, salt, _pbkdf2Iterations, HashAlgorithmName.SHA256))
            {
                key = kdf.GetBytes(_keySize);
            }
            aes.Key = key;

            // Send salt only
            await stream.WriteAsync(salt, 0, salt.Length);
            await stream.FlushAsync();
        }

        public static async Task ReadExactlyAsync(this Stream stream, byte[] buffer, int offset, int count)
        {
            int read = 0;
            while (read < count)
            {
                int readBytes = await stream.ReadAsync(buffer, offset + read, count - read);
                if (readBytes == 0)
                {
                    throw new EndOfStreamException();
                }

                read += readBytes;
            }
        }
    }
}
