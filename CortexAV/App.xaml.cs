using System.Configuration;
using System.Data;
using System.Windows;
using System.IO;
using System.Threading.Tasks;
using System.IO.Pipes;
using System.Threading;
using System.Windows.Media;
using CortexAV.Services;


namespace CortexAV
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private const string MutexName = "CortexAV_SingleInstance_Mutex_Secure";
        private const string PipeName = "CortexAV_Context_Pipe";
        private Mutex _mutex;

        protected override void OnStartup(StartupEventArgs e)
        {
            _mutex = new Mutex(true, MutexName, out bool createdNew);
            if (!createdNew)
            {
                if (e.Args.Length > 0)
                {
                    SendArgsToExistingInstance(e.Args[0]);
                }
                Current.Shutdown();
                return;

            }
            PythonEngineManager.StartEngine();
            base.OnStartup(e);
            Task.Run(() => ListenForContextScans());
            if (e.Args.Length > 0)
            {
                Task.Run(async () =>
                {
                    await Task.Delay(500);
                    Dispatcher.Invoke(()=>
                    { 
                        if(Current.MainWindow is MainWindow mainWindow)
                        {
                            mainWindow.ProcessExternalFile(e.Args[0]);
                        }

                    });
                });
            }

        }

        protected override void OnExit(ExitEventArgs e)
        {
            PythonEngineManager.StopEngine();
            base.OnExit(e);
        }

        private void SendArgsToExistingInstance(string filePath)
        {
            try
            {
                using (var client=new NamedPipeClientStream(".",PipeName,PipeDirection.Out))
                {
                    client.Connect(1000);
                    using (var writer=new StreamWriter(client))
                    {
                        writer.Write(filePath);
                        writer.Flush();
                    }

                }

            }
            catch (Exception) { }
        }

        private async Task ListenForContextScans()
        {

            while (true)
            {
                try
                {
                    using(var server= new NamedPipeServerStream(PipeName, PipeDirection.In))
                    {
                        await server.WaitForConnectionAsync();
                        using (var reader = new StreamReader(server)) 
                        {
                            string filePath = await reader.ReadToEndAsync();
                            if (!string.IsNullOrEmpty(filePath))
                            {
                                Dispatcher.Invoke(() =>
                                {
                                    if(Current.MainWindow is MainWindow mainWindow)
                                    {
                                        mainWindow.ProcessExternalFile(filePath);
                                    }

                                });
                            }
                        }

                    }
                }
                catch (Exception)
                {
                    await Task.Delay(1000);
                }
            }

        }

    }


}
