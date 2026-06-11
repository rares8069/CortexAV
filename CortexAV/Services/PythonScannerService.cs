using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Net.Http;
using System.Threading.Tasks;
using CortexAV.Models;


namespace CortexAV.Services
{
    public class PythonScannerService
    {
        private readonly string _pythonApiURL = "http://127.0.0.1:5000/scan";
        private static readonly HttpClient _httpClient = new HttpClient();

        public PythonScannerService() 
        {
            

        }

        public async Task<ScanResponse> AnalyzeFileAsync(string filePath)
        {
            try
            {

                var requestData = new { file_path = filePath };
                var jsonContent = new StringContent ( System.Text.Json.JsonSerializer.Serialize(requestData), Encoding.UTF8, "application/json");
                HttpResponseMessage response = await _httpClient.PostAsync(_pythonApiURL, jsonContent);
                response.EnsureSuccessStatusCode();

                string responseBody = await response.Content.ReadAsStringAsync();
                ScanResponse scanResult = System.Text.Json.JsonSerializer.Deserialize<ScanResponse>(responseBody);

                return scanResult;
            }
            catch(Exception ex)
            {

                throw new Exception($"Eroare la conectare cu motorul AI");
            }

        }


    }
}
