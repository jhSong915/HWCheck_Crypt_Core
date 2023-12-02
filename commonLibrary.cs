using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HWCheck_Crypt_Core
{
    public class commonLibrary
    {
        private SHA256Managed sha256 = new SHA256Managed();
        private RijndaelManaged aes = new RijndaelManaged();

        public string encrypt(string PlainString, string password)
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var salt = sha256.ComputeHash(Encoding.UTF8.GetBytes(password.Length.ToString()));
            var PBKDF2Key = new Rfc2898DeriveBytes(password, salt, 65535, HashAlgorithmName.SHA256);
            var secretKey = PBKDF2Key.GetBytes(aes.KeySize / 8);
            var iv = PBKDF2Key.GetBytes(aes.BlockSize / 8);
            byte[] bf = null;

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateEncryptor(secretKey, iv), CryptoStreamMode.Write))
                {
                    byte[] xXml = Encoding.UTF8.GetBytes(PlainString);
                    cs.Write(xXml, 0, xXml.Length);
                }
                bf = ms.ToArray();
            }
            String Output = Convert.ToBase64String(bf);
            return Output;
        }

        public string decrypt(string EncryptString, string password)
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            var salt = sha256.ComputeHash(Encoding.UTF8.GetBytes(password.Length.ToString()));
            var PBKDF2Key = new Rfc2898DeriveBytes(password, salt, 65535, HashAlgorithmName.SHA256);
            var secretKey = PBKDF2Key.GetBytes(aes.KeySize / 8);
            var iv = PBKDF2Key.GetBytes(aes.BlockSize / 8);
            byte[] bf = null;

            using (var ms = new MemoryStream())
            {
                using (var cs = new CryptoStream(ms, aes.CreateDecryptor(secretKey, iv), CryptoStreamMode.Write))
                {
                    byte[] xXml = Convert.FromBase64String(EncryptString);
                    cs.Write(xXml, 0, xXml.Length);
                }
                bf = ms.ToArray();
            }
            String Output = Encoding.UTF8.GetString(bf);
            return Output;
        }

        public string HardCheck()
        {
            string str = "";
            using (System.Management.ManagementObjectSearcher mos = new System.Management.ManagementObjectSearcher("select * from Win32_Processor"))
            {
                foreach (System.Management.ManagementObject Source in mos.Get())
                {
                    str += Source["ProcessorID"];
                }
            }
            str += "&";
            str += (from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up
                    select nic.GetPhysicalAddress().ToString()).FirstOrDefault();
            return str;
        }
    }
}
