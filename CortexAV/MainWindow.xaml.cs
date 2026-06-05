using CortexAV.Models;
using CortexAV.Services;
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

namespace CortexAV
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        private readonly PythonScannerService _scannerService;
        private string _currentFilePath = string.Empty;

        public MainWindow()
        {
            InitializeComponent();
            _scannerService = new PythonScannerService();

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

        private async void DropZone_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {

                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    _currentFilePath = files[0];//get dropped file
                    //UI SCANNING SCREEN
                    UploadPrompt.Visibility = Visibility.Collapsed;
                    ResultPanel.Visibility = Visibility.Visible;
                    TxtVerdict.Text = "Scanning";
                    TxtVerdict.Foreground = Brushes.Orange;
                    TxtScor.Text = "AI models are analyzing this file";
                    ActionButtons.Visibility = Visibility.Collapsed;

                    try
                    {
                        ScanResponse response = await _scannerService.AnalyzeFileAsync(_currentFilePath);
                        AfiseazaRezultat(response);

                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message, "AI Engine Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        ResetInterfata();
                    }



                }

            }


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
                string destinatie = System.IO.Path.Combine(folderCarantina, numeFisier + ".cortex");//extension

                if (File.Exists(_currentFilePath))
                {
                    File.Move(_currentFilePath, destinatie);
                    MessageBox.Show($"File was send to Quarantine succesfully","OK" ,MessageBoxButton.OK, MessageBoxImage.Information);
                    ResetInterfata();
                }



            }
            catch (Exception ex)
            {

                MessageBox.Show($"There was an error when moving the file","Error", MessageBoxButton.OK, MessageBoxImage.Warning);

            }
        }

        private void BtnReset_Click(object sender, RoutedEventArgs e) => ResetInterfata();

        private void ResetInterfata()
        {
            UploadPrompt.Visibility = Visibility.Visible;
            ResultPanel.Visibility = Visibility.Collapsed;
            _currentFilePath = string.Empty;
        }


    }
}