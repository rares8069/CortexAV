using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.Json;
using System.IO;
using System.Runtime;


namespace CortexAV.Core
{
    public class ScanRecord
    {
        public DateTime ScanDate { get; set; }
        public string FileName { get; set; }
        public string FilePath { get; set; }
        public string FileType { get; set;}
        public string Verdict {  get; set; }
        public double ConfidenceScore { get; set; }


    }

    public class AllowedThreat
    {
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string FileHash {  get; set; }
        public DateTime AddedDate {  get; set; }

    }

    public static class StorageManager
    {
        private static readonly string AppDataFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CortexAV");
        private static readonly string HistoryFile = Path.Combine(AppDataFolder, "history.json");
        private static readonly string WhitelistFile = Path.Combine(AppDataFolder, "whitelist.json");
        private static readonly string MonitoredFoldersFile = Path.Combine(AppDataFolder, "monitored_folders.json");
        public static List<string> MonitoredFolders { get; set; } = new List<string>();
        public static List<ScanRecord> ScanHistory { get; set; } = new List<ScanRecord>();
        public static List<AllowedThreat> Whitelist { get; set; } = new List<AllowedThreat>();

        private static readonly object _historyLock = new object();
        private static readonly object _whitelistLock = new object();
        private static readonly object _foldersLock = new object();


        public static void Initialize()
        {
            if (!Directory.Exists(AppDataFolder))
            {
                Directory.CreateDirectory(AppDataFolder);
            }

            LoadData();
        }

        public static void SaveMonitoredFolders()
        {
            File.WriteAllText(MonitoredFoldersFile,JsonSerializer.Serialize(MonitoredFolders,new JsonSerializerOptions { WriteIndented=true }));
        }

        public static void AddMonitoredFolder(string path)
        {
            lock (_foldersLock)
            {
                if (!MonitoredFolders.Contains(path, StringComparer.OrdinalIgnoreCase))
                {
                    MonitoredFolders.Add(path);
                    SaveMonitoredFolders();
                }
            }
        }

        public static void RemoveMonitoredFolder(string path)
        {
            lock (_foldersLock)
            {
                var item = MonitoredFolders.FirstOrDefault(f => f.Equals(path, StringComparison.OrdinalIgnoreCase));
                if (item != null)
                {
                    MonitoredFolders.Remove(path);
                    SaveMonitoredFolders();
                }
            }
        }

        public static void SaveHistory(ScanRecord record)
        {
            lock (_historyLock)
            {
                ScanHistory.Add(record);
                File.WriteAllText(HistoryFile, JsonSerializer.Serialize(ScanHistory, new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        public static void SaveToWhiteList(AllowedThreat threat)
        {
            lock (_whitelistLock)
            {
                Whitelist.Add(threat);
                File.WriteAllText(WhitelistFile, JsonSerializer.Serialize(Whitelist, new JsonSerializerOptions { WriteIndented = true }));
            }

        }

        private static void LoadData()
        {
            if (File.Exists(HistoryFile))
            {
                string json = File.ReadAllText(HistoryFile);
                ScanHistory = JsonSerializer.Deserialize<List<ScanRecord>>(json) ?? new List<ScanRecord>();
            }
            if (File.Exists(WhitelistFile))
            {
                string json = File.ReadAllText(WhitelistFile);
                Whitelist = JsonSerializer.Deserialize<List<AllowedThreat>>(json) ?? new List<AllowedThreat>();


            }
            if (File.Exists(MonitoredFoldersFile))
            {
                string json=File.ReadAllText(MonitoredFoldersFile);
                MonitoredFolders = JsonSerializer.Deserialize<List<string>>(json) ?? new List<string>();
            }
            else
            {
                string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                MonitoredFolders.Add(downloadsPath);
                SaveMonitoredFolders();
            }

        }

        public static bool IsFileAllowed(string fileName,long fileSize, string fileHash)
        {
            lock (_whitelistLock)
            {
                foreach (var threat in Whitelist)
                {
                    if (threat.FileName == fileName && threat.FileSize == fileSize && threat.FileHash == fileHash)
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        public static void ClearHistory()
        {
            lock (_historyLock)     
            { 
                ScanHistory.Clear();
                File.WriteAllText(HistoryFile, JsonSerializer.Serialize(ScanHistory, new JsonSerializerOptions { WriteIndented = true }));
            }

        }

        public static void RemoveFromWhitelist(string fileHash)
        {
            lock (_whitelistLock)
            {
                var item = Whitelist.FirstOrDefault(w => w.FileHash == fileHash);
                if (item != null)
                {
                    Whitelist.Remove(item);
                    File.WriteAllText(WhitelistFile, JsonSerializer.Serialize(Whitelist, new JsonSerializerOptions { WriteIndented = true }));
                }
            }
        }

    }
}
