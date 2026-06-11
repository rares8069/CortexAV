using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace CortexAV.Core
{
    public static class FileHasher
    {
        public static string CalculateSHA256(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create()) 
                { 
                
                    using (var stream = File.OpenRead(filePath))
                    {
                        var hash= sha256.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-","").ToLowerInvariant();

                    }

                }
            }
            catch (Exception)
            {
                return null;
            }


        }

    }
}
