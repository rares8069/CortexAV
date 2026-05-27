using CortexAV.Services;
using CortexAV.Models;
using System.Text;
using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

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



    }
}