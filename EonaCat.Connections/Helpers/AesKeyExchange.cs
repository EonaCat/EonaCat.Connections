using System.Security.Cryptography;
using System.Text;

namespace EonaCat.Connections.Helpers
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public static class AesKeyExchange
    {
        // 256-bit salt
        private const int _saltSize = 32;

        // 128-bit IV
        private const int _ivSize = 16;

        // 256-bit AES key
        private const int _aesKeySize = 32;

        // 256-bit HMAC key (key confirmation)
        private const int _hmacKeySize = 32;

        // PBKDF2 iterations
        private const int _iterations = 800_000;

        private static readonly byte[] KeyConfirmationLabel = Encoding.UTF8.GetBytes("KEYCONFIRMATION");

        public static async Task<byte[]> EncryptDataAsync(byte[] data, Aes aes)
        {
            using (var encryptor = aes.CreateEncryptor())
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data, 0, data.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        public static async Task<byte[]> DecryptDataAsync(byte[] data, Aes aes)
        {
            using (var decryptor = aes.CreateDecryptor())
            using (var ms = new MemoryStream(data))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var result = new MemoryStream())
            {
                await cs.CopyToAsync(result);
                return result.ToArray();
            }
        }

        public static async Task<Aes> SendAesKeyAsync(Stream stream, Aes aes, string password)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (aes == null)
            {
                throw new ArgumentNullException(nameof(aes));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password/PSK required", nameof(password));
            }

            var salt = RandomBytes(_saltSize);
            var iv = RandomBytes(_ivSize);

            // Derive AES key and HMAC key (for key confirmation)
            var keyMaterial = DeriveKey(password, salt, _aesKeySize + _hmacKeySize);
            var aesKey = new byte[_aesKeySize];
            var hmacKey = new byte[_hmacKeySize];
            Buffer.BlockCopy(keyMaterial, 0, aesKey, 0, _aesKeySize);
            Buffer.BlockCopy(keyMaterial, _aesKeySize, hmacKey, 0, _hmacKeySize);

            // Compute key confirmation HMAC = HMAC(hmacKey, "KEYCONFIRM" || salt || iv)
            byte[] keyConfirm;
            using (var h = new HMACSHA256(hmacKey))
            {
                h.TransformBlock(KeyConfirmationLabel, 0, KeyConfirmationLabel.Length, null, 0);
                h.TransformBlock(salt, 0, salt.Length, null, 0);
                h.TransformFinalBlock(iv, 0, iv.Length);
                keyConfirm = h.Hash;
            }

            // Send: salt, iv, keyConfirm (each length-prefixed 4-byte big-endian)
            await WriteWithLengthAsync(stream, salt).ConfigureAwait(false);
            await WriteWithLengthAsync(stream, iv).ConfigureAwait(false);
            await WriteWithLengthAsync(stream, keyConfirm).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);

            // Configure AES and return
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = aesKey;
            aes.IV = iv;

            return aes;
        }

        public static async Task<Aes> ReceiveAesKeyAsync(Stream stream, string password)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password/PSK required", nameof(password));
            }

            var salt = await ReadWithLengthAsync(stream).ConfigureAwait(false);
            var iv = await ReadWithLengthAsync(stream).ConfigureAwait(false);
            var keyConfirm = await ReadWithLengthAsync(stream).ConfigureAwait(false);

            if (salt == null || salt.Length != _saltSize)
            {
                throw new InvalidOperationException("Invalid salt length");
            }

            if (iv == null || iv.Length != _ivSize)
            {
                throw new InvalidOperationException("Invalid IV length");
            }

            var keyMaterial = DeriveKey(password, salt, _aesKeySize + _hmacKeySize);
            var aesKey = new byte[_aesKeySize];
            var hmacKey = new byte[_hmacKeySize];
            Buffer.BlockCopy(keyMaterial, 0, aesKey, 0, _aesKeySize);
            Buffer.BlockCopy(keyMaterial, _aesKeySize, hmacKey, 0, _hmacKeySize);

            byte[] expected;
            using (var h = new HMACSHA256(hmacKey))
            {
                h.TransformBlock(KeyConfirmationLabel, 0, KeyConfirmationLabel.Length, null, 0);
                h.TransformBlock(salt, 0, salt.Length, null, 0);
                h.TransformFinalBlock(iv, 0, iv.Length);
                expected = h.Hash;
            }

            if (!FixedTimeEquals(expected, keyConfirm))
            {
                throw new CryptographicException("Key confirmation failed - wrong password or tampered data");
            }

            var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = aesKey;
            aes.IV = iv;

            return aes;
        }


        private static async Task WriteWithLengthAsync(Stream stream, byte[] data)
        {
            var byteLength = BitConverter.GetBytes(data.Length);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(byteLength);
            }

            await stream.WriteAsync(byteLength, 0, 4).ConfigureAwait(false);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        private static async Task<byte[]> ReadWithLengthAsync(Stream stream)
        {
            var bufferLength = new byte[4];
            await ReadExactlyAsync(stream, bufferLength, 0, 4).ConfigureAwait(false);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bufferLength);
            }

            int length = BitConverter.ToInt32(bufferLength, 0);
            if (length < 0 || length > 10_000_000)
            {
                throw new InvalidOperationException("Invalid length");
            }

            var buffer = new byte[length];
            await ReadExactlyAsync(stream, buffer, 0, length).ConfigureAwait(false);
            return buffer;
        }

        private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int read = await stream.ReadAsync(buffer, offset + total, count - total).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException("Stream ended prematurely");
                }

                total += read;
            }
        }

        private static byte[] DeriveKey(string password, byte[] salt, int size)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, _iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(size);
            }
        }

        private static byte[] RandomBytes(int n)
        {
            var b = new byte[n];
            using (var random = RandomNumberGenerator.Create())
            {
                random.GetBytes(b);
            }

            return b;
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            int difference = 0;
            for (int i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }

            return difference == 0;
        }
    }
}
