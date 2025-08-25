using System.Security.Cryptography;
using System.Text;

namespace EonaCat.Connections.Helpers
{
    // This file is part of the EonaCat project(s) which is released under the Apache License.
    // See the LICENSE file or go to https://EonaCat.com/license for full license details.

    public static class AesCryptoHelpers
    {
        private static readonly byte[] HmacInfo = Encoding.UTF8.GetBytes("EonaCat.Connections.HMAC");

        public static async Task<byte[]> EncryptDataAsync(byte[] plaintext, Aes aes)
        {
            byte[] iv = new byte[aes.BlockSize / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            byte[] ciphertext;
            using (var encryptor = aes.CreateEncryptor(aes.Key, iv))
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(plaintext, 0, plaintext.Length);
                cs.FlushFinalBlock();
                ciphertext = ms.ToArray();
            }

            byte[] hmacKey = DeriveHmacKey(aes.Key);
            byte[] toAuth = iv.Concat(ciphertext).ToArray();
            byte[] hmac;
            using (var h = new HMACSHA256(hmacKey))
            {
                hmac = h.ComputeHash(toAuth);
            }

            return toAuth.Concat(hmac).ToArray();
        }

        public static async Task<byte[]> DecryptDataAsync(byte[] payload, Aes aes)
        {
            int ivLen = aes.BlockSize / 8;
            int hmacLen = 32;

            if (payload.Length < ivLen + hmacLen)
            {
                throw new CryptographicException("Payload too short");
            }

            byte[] iv = payload.Take(ivLen).ToArray();
            byte[] ciphertext = payload.Skip(ivLen).Take(payload.Length - ivLen - hmacLen).ToArray();
            byte[] receivedHmac = payload.Skip(payload.Length - hmacLen).ToArray();

            byte[] hmacKey = DeriveHmacKey(aes.Key);
            byte[] toAuth = iv.Concat(ciphertext).ToArray();
            byte[] computed;
            using (var h = new HMACSHA256(hmacKey))
            {
                computed = h.ComputeHash(toAuth);
            }

            if (!FixedTimeEquals(computed, receivedHmac))
            {
                throw new CryptographicException("HMAC validation failed: message tampered or wrong key");
            }

            byte[] plaintext;
            using (var decryptor = aes.CreateDecryptor(aes.Key, iv))
            using (var ms = new MemoryStream(ciphertext))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var result = new MemoryStream())
            {
                await cs.CopyToAsync(result);
                plaintext = result.ToArray();
            }

            return plaintext;
        }

        private static byte[] DeriveHmacKey(byte[] aesKey)
        {
            using var h = new HMACSHA256(aesKey);
            return h.ComputeHash(HmacInfo);
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }
    }

}
