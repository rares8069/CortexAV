using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CortexAV.Core;
using CortexAV.Models;
using System.IO;
using CortexAV.Services;
using System.Collections.Concurrent;


namespace CortexAV.Core
{
    public class RealTimeMonitor
    {
        private readonly PythonScannerService _scannerService;
        private readonly Dictionary<string,FileSystemWatcher> _watchers;
        private readonly string[] _targetExtension = { ".exe", ".dll", ".sys", ".msi", ".bat", ".ps1" };
        

        public event EventHandler<ScanRecord> OnFileScanned;

        private readonly ConcurrentQueue<string> _scanQueue;
        private readonly CancellationTokenSource _cancellationTokenSource;

        public RealTimeMonitor(PythonScannerService scannerService)
        {
            _scannerService = scannerService;
            _watchers = new Dictionary<string, FileSystemWatcher>(StringComparer.OrdinalIgnoreCase);

            _scanQueue = new ConcurrentQueue<string>();
            _cancellationTokenSource=new CancellationTokenSource();

            Task.Run(() => ProcessQueueAsync(_cancellationTokenSource.Token));
        }

        public void SyncWithStorage()
        {
            StopAll();
            foreach(var folderPath in StorageManager.MonitoredFolders)
            {
                StartMonitoring(folderPath);
            }
        }

        public void StartMonitoring(string directoryPath)
        {
            if (!Directory.Exists(directoryPath)) return;
            if (_watchers.ContainsKey(directoryPath)) return;

            var watcher = new FileSystemWatcher(directoryPath)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                IncludeSubdirectories =false
            };
            watcher.Created += Watcher_Created;
            watcher.EnableRaisingEvents = true;
            _watchers[directoryPath] = watcher;
        }

        public void StopMonitoring(string directoryPath)
        {
            if(_watchers.TryGetValue(directoryPath,out var watcher))
            {
                watcher.EnableRaisingEvents = false;
                watcher.Created -= Watcher_Created;
                watcher.Dispose();
                _watchers.Remove(directoryPath);
            }
        }

        public void StopAll()
        {

            foreach(var watcher in _watchers.Values)
            {

                watcher.EnableRaisingEvents = false;
                watcher.Created-= Watcher_Created;
                watcher.Dispose();
            }

            _watchers.Clear();
        }

        private async void Watcher_Created(object sender, FileSystemEventArgs e)
        {
            if (Directory.Exists(e.FullPath)) return;

            string ext = Path.GetExtension(e.FullPath).ToLowerInvariant();
            if (!_targetExtension.Contains(ext)) return;

            _scanQueue.Enqueue(e.FullPath);
        }
        private async Task ProcessQueueAsync(CancellationToken cancellationToken) {


            while (!cancellationToken.IsCancellationRequested)
            {
                if(_scanQueue.TryDequeue(out string path))
                {
                    await ProceessSingleFileAsync(path);
                }
                else
                {
                    await Task.Delay(500, cancellationToken);
                }

            }

        }

        private async Task ProceessSingleFileAsync(string filePath)
        {
            try 
            { 
            bool isReady = await WaitForFileASync(filePath);
            if (!isReady) return;

            var fileInfo = new FileInfo(filePath);

            string hash = await Task.Run(() => FileHasher.CalculateSHA256(filePath));

            if (hash != null & StorageManager.IsFileAllowed(fileInfo.Name, fileInfo.Length, hash))
            {
                return;
            }

                ScanResponse response = await _scannerService.AnalyzeFileAsync(filePath);

                var record = new ScanRecord
                {
                    ScanDate = DateTime.Now,
                    FileName = fileInfo.Name,
                    FilePath = fileInfo.FullName,
                    FileType = fileInfo.Extension,
                    Verdict = response.Verdict,
                    ConfidenceScore = response.ConfidenceScore

                };

                StorageManager.SaveHistory(record);

                if (response.Verdict == "Malware")
                {
                    StorageManager.AutoQuarantine(filePath);
                }

                OnFileScanned?.Invoke(this, record);


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Erpare la scanarea RealTime {ex.Message}");
            }
        }
        private async Task<bool> WaitForFileASync(string filePath,int maxRetries=100,int delayMs = 1000)
        {
            for(int i = 0; i < maxRetries; i++)
            {
                try
                {
                    using (FileStream fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
                    {
                        return true;
                    }
                }
                catch (IOException)
                {
                    await Task.Delay(delayMs);
                }
            }
            return false;

        }  

    }
}
