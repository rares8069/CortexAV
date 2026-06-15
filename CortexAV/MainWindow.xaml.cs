using CortexAV.Models;
using CortexAV.Services;
using CortexAV.Core;
using System;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using static System.Net.Mime.MediaTypeNames;
using System.IO.Enumeration;
using System.Linq;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using Microsoft.Toolkit.Uwp.Notifications;

namespace CortexAV
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        private readonly PythonScannerService _scannerService;
        private string _currentFilePath = string.Empty;
        private readonly RealTimeMonitor _realTimeMonitor;

        private ObservableCollection<string> _scanQueueUI = new ObservableCollection<string>();
        private ObservableCollection<string> _safeFilesUI= new ObservableCollection<string>();
        private ObservableCollection<string> _malwareFilesUI=new ObservableCollection<string>();
        private bool _isBatchScanning = false;
        private bool _isDashBoardBusy = false;

        public MainWindow()
        {

            InitializeComponent();
            StorageManager.Initialize();
            _scannerService = new PythonScannerService();
            _realTimeMonitor = new RealTimeMonitor(_scannerService);
            _realTimeMonitor.OnFileScanned += RealTimeMonitor_OnFileScanned;
            _realTimeMonitor.SyncWithStorage();
            ListQueue.ItemsSource= _scanQueueUI;
            ListSafe.ItemsSource    = _safeFilesUI;
            ListMalware.ItemsSource = _malwareFilesUI;
            //RefreshDataGrids();
        }

        private void RealTimeMonitor_OnFileScanned(object sender, ScanRecord record)
        {
            Dispatcher.Invoke(() =>
            {
                RefreshDataGrids();
                //MessageBox.Show($"Real-Time alert\n Detected {record.FileName}\nVerdict:{record.Verdict} ({record.ConfidenceScore:F2}%)", "CortexAV Monitor", MessageBoxButton.OK, MessageBoxImage.Information);

                if (this.WindowState == WindowState.Minimized && record.Verdict == "Malware")
                {
                    new ToastContentBuilder()
                        .AddArgument("action", "viewQuarantine")
                        .AddText("CortexAV - Threat Blocked Succesfully")
                        .AddText($"Dangerous File:{record.FileName} was moved to Quarantine")
                        .AddAudio(new Uri("ms-winsoundevent:Notification.Im"))
                        .Show();

                }


            });

           
        }

        private void DropZone_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
            }
            else
            {
                e.Effects = DragDropEffects.None;
            }

        }

        protected override void OnStateChanged(EventArgs e)
        {
            base.OnStateChanged(e);
            if (this.WindowState == WindowState.Minimized&& !_isDashBoardBusy)
            {
               // ResetInterfata();
            }
        }

        private async Task StartSingleFileScanAsync(string filePath)
        {
            if (_isDashBoardBusy)
            {
                MessageBox.Show("One file is already being scanned.Please wait", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            _isDashBoardBusy = true;

            _currentFilePath = filePath;
            UploadPrompt.Visibility = Visibility.Collapsed;
            ResultPanel.Visibility = Visibility.Visible;

            // --- ASCUNDEM BUTONUL DE REFRESH AICI ---
            if (BtnRefreshDashboard != null) BtnRefreshDashboard.Visibility = Visibility.Collapsed;

            TxtVerdict.Text = "Scanning...";
            TxtVerdict.Foreground = Brushes.Orange;
            TxtScor.Text = "AI models are analyzing this file";
            ActionButtons.Visibility = Visibility.Collapsed;

            try
            {
                ScanResponse response = await _scannerService.AnalyzeFileAsync(_currentFilePath);
                AfiseazaRezultat(response);
                _isDashBoardBusy = false;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "AI Engine Error", MessageBoxButton.OK, MessageBoxImage.Error);
                ResetInterfata();
            }
        }

        private async void DropZone_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {

                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    //_currentFilePath = files[0];//get dropped file
                    await StartSingleFileScanAsync(files[0]);
                }

            }


        }



        public async void ProcessExternalFile(string filePath)
        {


            ViewDashboard.Visibility = Visibility.Visible;
            ViewHistory.Visibility = Visibility.Collapsed;
            ViewWhitelist.Visibility = Visibility.Collapsed;
            ViewMonitor.Visibility = Visibility.Collapsed;
            ViewCustomScan.Visibility = Visibility.Collapsed;
            ViewQuarantine.Visibility = Visibility.Collapsed;

            if (this.WindowState == WindowState.Minimized)
            {
                this.WindowState = WindowState.Normal;
            }
            this.Activate();
            this.Topmost = true;
            this.Topmost = false;
            this.Focus();

            string ext = System.IO.Path.GetExtension(filePath).ToLower();
            if (ext != null)
            {
                await StartSingleFileScanAsync(filePath);
            }
            else
            {
                MessageBox.Show("There was an error when processing this file","Error",MessageBoxButton.OK, MessageBoxImage.Error);
            }


        }

        private async void AllowThreat_Click(object sender, RoutedEventArgs e)
        {

            if(string.IsNullOrEmpty(_currentFilePath)|| !File.Exists(_currentFilePath)) return;

            try
            {
                var fileInfo=new FileInfo(_currentFilePath);
                string hash = await Task.Run(() => FileHasher.CalculateSHA256(_currentFilePath));

                if (hash != null)
                {
                    var allowedThreat = new AllowedThreat
                    {
                        FileName = fileInfo.Name,
                        FileSize = fileInfo.Length,
                        FileHash = hash,
                        AddedDate = DateTime.Now
                    };

                    StorageManager.SaveToWhiteList(allowedThreat);
                    MessageBox.Show("File was succesfully added in WhiteList");

                    ResetInterfata();
                }

            }
            catch(Exception ex)
            {
                MessageBox.Show($"error adding in whitelist {ex.Message}");
            }

        }

        private void BtnMenuDashboard_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Visible;
            ViewHistory.Visibility = Visibility.Collapsed;
            ViewWhitelist.Visibility = Visibility.Collapsed;
            ViewMonitor.Visibility = Visibility.Collapsed;
            ViewCustomScan.Visibility = Visibility.Collapsed;
            ViewQuarantine.Visibility = Visibility.Collapsed;
            //RefreshDataGrids();

        }

        private void BtnMenuHistory_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Visible;
            ViewWhitelist.Visibility = Visibility.Collapsed;
            ViewMonitor.Visibility = Visibility.Collapsed;
            ViewCustomScan.Visibility = Visibility.Collapsed;
            ViewQuarantine.Visibility = Visibility.Collapsed;
            RefreshDataGrids();
        }

        private void BtnMenuWhitelist_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Collapsed;
            ViewWhitelist.Visibility = Visibility.Visible;
            ViewMonitor.Visibility = Visibility.Collapsed;
            ViewCustomScan.Visibility = Visibility.Collapsed;
            ViewQuarantine.Visibility = Visibility.Collapsed;
            RefreshDataGrids();
        }

        private void BtnMenuMonitor_Click(object sender, RoutedEventArgs e)
        {

            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewWhitelist.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Collapsed;
            ViewMonitor.Visibility = Visibility.Visible;
            ViewCustomScan.Visibility = Visibility.Collapsed;
            ViewQuarantine.Visibility = Visibility.Collapsed;
            RefreshDataGrids();

        }

        private void BtnMenuCustomScan_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewWhitelist.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Collapsed;
            ViewMonitor.Visibility = Visibility.Collapsed;
            ViewCustomScan.Visibility = Visibility.Visible;
            ViewQuarantine.Visibility = Visibility.Collapsed;
            RefreshDataGrids();

        }

        private void BtnMenuQuarantine_Click(object sender, RoutedEventArgs e)
        {

            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewWhitelist.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Collapsed;
            ViewMonitor.Visibility = Visibility.Collapsed;
            ViewCustomScan.Visibility = Visibility.Collapsed;
            ViewQuarantine.Visibility = Visibility.Visible;
            RefreshDataGrids();
        }

        private void RefreshDataGrids()
        {
            if (GridHistory != null)
            {
                GridHistory.ItemsSource = null;
                GridHistory.ItemsSource = StorageManager.ScanHistory.ToArray().Reverse();

            }

            if (GridWhitelist != null)
            {
                GridWhitelist.ItemsSource = null;
                GridWhitelist.ItemsSource = StorageManager.Whitelist.ToArray().Reverse();
            }

            if(ListFolders != null)
            {
                ListFolders.ItemsSource = null;
                ListFolders.ItemsSource = StorageManager.MonitoredFolders;//.ToArray().Reverse();
            }

            if (GridQuarantine != null) { 

                GridQuarantine.ItemsSource = null;
                GridQuarantine.ItemsSource=StorageManager.QuarantinedFiles.ToArray().Reverse();
            }
        }


        private void BtnClearHistory_Click(object sender, RoutedEventArgs e)
        {

            var result = MessageBox.Show("Are you sure that you want to delete th history","Confirmare",MessageBoxButton.YesNo,MessageBoxImage.Warning);
            if (result == MessageBoxResult.Yes)
            {
                StorageManager.ClearHistory();
                RefreshDataGrids();
            }

        }

        private async void BtnAddWhitelist_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = "Add a file to the Whitelist",
                Filter="executables (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All Files (*.*)|*.*"
            };

            if(openFileDialog.ShowDialog()== true)
            {
                string filePath=openFileDialog.FileName;
                try
                {
                    var fileInfo = new FileInfo(filePath);
                    string hash = await Task.Run(() => FileHasher.CalculateSHA256(filePath));

                    if(hash != null)
                    {

                        if (StorageManager.Whitelist.Any(w => w.FileHash == hash)) 
                        {
                            MessageBox.Show("File already in whitelist");
                            return;
                        }

                        var allowedThreat = new AllowedThreat
                        {
                            FileName=fileInfo.Name,
                            FileSize=fileInfo.Length,
                            FileHash=hash,
                            AddedDate=DateTime.Now

                        };

                        StorageManager.SaveToWhiteList(allowedThreat);
                        RefreshDataGrids();

                    }

                }
                catch(Exception ex)
                {
                    MessageBox.Show("Error processing this file","Eroare", MessageBoxButton.OK, MessageBoxImage.Error);

                }
            }
        }

        private void BtnRemoveWhitelist_Click(object sender, RoutedEventArgs e)
        {

            if(GridWhitelist.SelectedItem is AllowedThreat selectedThreat)
            {
                var result= MessageBox.Show("Are you sure that you want to eliminate this file","Confirm",MessageBoxButton.YesNo,MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    StorageManager.RemoveFromWhitelist(selectedThreat.FileHash);
                    RefreshDataGrids();
                }
            }
            else
            {
                MessageBox.Show("Please select a file","Caution",MessageBoxButton.OK,MessageBoxImage.Warning);
            }

        }

       

        private void BtnAddFolder_Click(object sender, RoutedEventArgs e)
        {

            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title="Select the folder that you want to protect"
            };

            if (dialog.ShowDialog() == true)
            {
                string selectedPath = dialog.FolderName;
                StorageManager.AddMonitoredFolder(selectedPath);
                _realTimeMonitor.StartMonitoring(selectedPath);
                RefreshDataGrids();
            }

        }

        private void BtnRemoveFolder_Click(object sender, RoutedEventArgs e)
        {
            if(ListFolders.SelectedItem is string selectedFolder)
            {
                var result=MessageBox.Show("Are you sure that you want to remove this folder","Attention",MessageBoxButton.YesNo,MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes) {
                    StorageManager.RemoveMonitoredFolder(selectedFolder);
                    _realTimeMonitor.StopMonitoring(selectedFolder);
                    RefreshDataGrids() ;
                }
            }
            else
            {
                MessageBox.Show("Please select a folder", "Attention", MessageBoxButton.OK,MessageBoxImage.Warning);
            }

        }

        private void BtnRestoreQuarantine_Click(object sender, RoutedEventArgs e)
        {
            if(GridQuarantine.SelectedItem is QuarantinedItem selectedItem)
            {
                var result = MessageBox.Show($"Do you want to restore {selectedItem.FileName} ?", "Security", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    try
                    {

                        string originalDirectory = System.IO.Path.GetDirectoryName(selectedItem.OriginalPath);
                        if (!Directory.Exists(originalDirectory))
                        {
                            Directory.CreateDirectory(originalDirectory);
                        }

                        if (File.Exists(selectedItem.QuarantinedPath))
                        {
                            File.Move(selectedItem.QuarantinedPath, selectedItem.OriginalPath);
                            StorageManager.RemoveFromQuarantineLog(selectedItem.QuarantinedPath);
                            MessageBox.Show("File was restored succesfuly","Information",MessageBoxButton.OK,MessageBoxImage.Information);
                            RefreshDataGrids();
                        }
                        else
                        {
                            MessageBox.Show("File no longer in Quarantine","Error",MessageBoxButton.OK, MessageBoxImage.Warning);
                            StorageManager.RemoveFromQuarantineLog(selectedItem.QuarantinedPath);
                            RefreshDataGrids();
                        }

                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"There was an error trying to restore {ex.Message} ","Error ",MessageBoxButton.OK,MessageBoxImage.Error);
                    }



                }

            }
            else
            {
                MessageBox.Show("Select a file from the list", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }

        }

        private void BtnDeleteQuarantine_Click(object sender, EventArgs e)
        {
            if(GridQuarantine.SelectedItem is QuarantinedItem selectedItem)
            {
                var result=MessageBox.Show($"Are you sure that you want to delete {selectedItem.FileName}.This action cannot be undone","Delete",MessageBoxButton.YesNo,MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    if (File.Exists(selectedItem.QuarantinedPath))
                    {
                        File.Delete(selectedItem.QuarantinedPath);
                    }

                    StorageManager.RemoveFromQuarantineLog(selectedItem.QuarantinedPath);
                    RefreshDataGrids();

                }

            }
            else
            {
                MessageBox.Show("Please select a file from the list", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
            }

        }

        private async void BtnSelectFilesToScan_Click(object sender, RoutedEventArgs e)
        {
            // AICI E SECRETUL: Prindem butonul pe care ai dat click!
            if (sender is Button clickedButton)
            {
                OpenFileDialog dialog = new OpenFileDialog
                {
                    Multiselect = true,
                    Title = "Select Files to scan ",
                    Filter = "Executabile (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|Toate fisierele(*.*)|*.*"
                };

                if (dialog.ShowDialog() == true)
                {
                    // NU mai folosim "BtnSelectFilesToScan", folosim direct "clickedButton"
                    clickedButton.IsHitTestVisible = false;
                    clickedButton.Content = "Scanning..";

                    foreach (string filePath in dialog.FileNames)
                    {
                        if (!_scanQueueUI.Contains(filePath))
                        {
                            _scanQueueUI.Add(filePath);
                        }
                    }

                    await ProcessBatchQueueAsync();

                    clickedButton.IsHitTestVisible = true;
                    clickedButton.Content = "Selectează Fișiere...";
                }
            }
        }

        private async Task ProcessBatchQueueAsync()
        {
            _isBatchScanning = true;
            while (true)
            {
                string currentFile = null;
                Dispatcher.Invoke(() =>
                {
                    if (_scanQueueUI.Count > 0) {
                        currentFile = _scanQueueUI[0];
                    }
                }
                );

                if (currentFile == null) {
                    break;
                }

                try
                {
                    var fileInfo = new FileInfo(currentFile);
                    string hash = await Task.Run(() => FileHasher.CalculateSHA256(currentFile));

                    bool isWhitelisted=(hash!=null&&StorageManager.IsFileAllowed(fileInfo.Name,fileInfo.Length,hash));
                    ScanResponse response = null;

                    if (!isWhitelisted)
                    {

                        response = await _scannerService.AnalyzeFileAsync(currentFile);
                        var record = new ScanRecord
                        {
                            ScanDate=DateTime.Now,
                            FileName= fileInfo.Name,
                            FilePath    =fileInfo.FullName,
                            FileType=fileInfo.Extension,
                            Verdict=response.Verdict,
                            ConfidenceScore=response.ConfidenceScore

                        };
                        StorageManager.SaveHistory(record);

                        if (response.Verdict == "Malware")
                        {
                            StorageManager.AutoQuarantine(currentFile);
                        }
                    }

                    Dispatcher.Invoke(()
                        =>
                    {
                        _scanQueueUI.Remove(currentFile);
                        string displayItem=fileInfo.Name;
                        if(isWhitelisted)
                        {
                            _safeFilesUI.Add($"Fisier Exceptat {displayItem}");
                        }else if(response!=null && response.Verdict == "Malware")
                        {
                            _malwareFilesUI.Add($"{displayItem}:{response.Verdict} File was succesfuly moved to quarantine");
                        }else
                        {
                            _safeFilesUI.Add($"{displayItem}: {response?.ConfidenceScore:F1}%");
                        }
                    }
                        );

                }
                catch (Exception)
                {
                    Dispatcher.Invoke(() =>
                    {
                        _scanQueueUI.Remove(currentFile);
                        _malwareFilesUI.Add($"Error reading {System.IO.Path.GetFileName(currentFile)}");
                    });
                      
                }


            }

            _isBatchScanning = false;
        }

        private void AfiseazaRezultat(ScanResponse response)
        {
            TxtScor.Text = $"Trust Score:{response.ConfidenceScore.ToString("F2")}% \nDetalii: {response.Details}";

            if (response.Verdict.Equals("Malware", StringComparison.OrdinalIgnoreCase))
            {
                TxtVerdict.Text = "Malware Detected!";
                TxtVerdict.Foreground = Brushes.Red;
                ActionButtons.Visibility = Visibility.Visible;
            }
            else
            {
                TxtVerdict.Text = "Safe File";
                TxtVerdict.Foreground = Brushes.LimeGreen;
                ActionButtons.Visibility = Visibility.Collapsed;
            }

            // --- AFIȘĂM BUTONUL DE REFRESH AICI (pentru ambele cazuri) ---
            if (BtnRefreshDashboard != null) BtnRefreshDashboard.Visibility = Visibility.Visible;

            var fileInfo = new System.IO.FileInfo(_currentFilePath);
            StorageManager.SaveHistory(new ScanRecord
            {
                ScanDate = DateTime.Now,
                FileName = fileInfo.Name,
                FilePath = fileInfo.FullName,
                FileType = fileInfo.Extension,
                Verdict = response.Verdict,
                ConfidenceScore = response.ConfidenceScore
            });
        }

        private void Delete_Click(object sender, EventArgs e)
        {

            try
            {

                if (File.Exists(_currentFilePath))
                {
                    File.Delete(_currentFilePath);
                    MessageBox.Show("File was deleted succesfully");
                    ResetInterfata();
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show("Cant deleted specified file");
            }


        }

        private void Quarantine_Click(object sender, EventArgs e)
        {

            try
            {
                string folderCarantina = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Quarantine");
                if (!Directory.Exists(folderCarantina))
                {
                    Directory.CreateDirectory(folderCarantina);
                }

                string numeFisier = System.IO.Path.GetFileName(_currentFilePath);
                string codUnic = Guid.NewGuid().ToString().Substring(0, 8);
                string destinatie = System.IO.Path.Combine(folderCarantina, $"{numeFisier}_{codUnic}.cortex");
                if (File.Exists(_currentFilePath)) {

                File.Move(_currentFilePath, destinatie);
                    var qItem = new QuarantinedItem
                    {
                        FileName=numeFisier,
                        OriginalPath=_currentFilePath,
                        QuarantinedPath=destinatie,
                        QuarantineDate=DateTime.Now
                    };

                    StorageManager.SaveToQuarantine(qItem);
                    MessageBox.Show("File was succesfully moved to quarantine", "Security", MessageBoxButton.OK, MessageBoxImage.Information);
                    ResetInterfata();
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error moving a file to quarantine{ex.Message}","Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            
        }

        private void BtnReset_Click(object sender, RoutedEventArgs e) => ResetInterfata();

        private void ResetInterfata()
        {
            UploadPrompt.Visibility = Visibility.Visible;
            ResultPanel.Visibility = Visibility.Collapsed;
            _currentFilePath = string.Empty;
            _isDashBoardBusy = false;
        }


    }
}