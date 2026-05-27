using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json.Serialization;

namespace CortexAV.Models
{
    public class ScanResponse
    {
        [JsonPropertyName("verdict")]
        public string Verdict { get; set; }

        [JsonPropertyName("confidence_score")]
        public double ConfidenceScore { get; set; }

        [JsonPropertyName("details")]
        public string Details { get; set; }


    }

}
