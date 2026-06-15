using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace CortexAV.Services
{
    internal class PythonEngineManager
    {

        private static Process _pythonProcess;

        public static void StartEngine()
        {

           string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
           string pythonExe = System.IO.Path.Combine(userProfile, @"Documents\GitHub\Licenta\CortexAV\AI_Engine\.venv\Scripts\python.exe");
           string scriptPath = System.IO.Path.Combine(userProfile, @"Documents\GitHub\Licenta\CortexAV\AI_Engine\src\AiEngine.py");

            var psi = new ProcessStartInfo
            {
                FileName = pythonExe,
                Arguments = $"\"{scriptPath}\"",

                
                WorkingDirectory = Path.GetDirectoryName(scriptPath),

                UseShellExecute = false,
                CreateNoWindow = true, // Lasă FALSE până merge!
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            _pythonProcess = new Process { StartInfo = psi };

            // Captură erori
            _pythonProcess.ErrorDataReceived += (s, e) => Console.WriteLine($"[PYTHON ERR]: {e.Data}");
            _pythonProcess.OutputDataReceived += (s, e) => Console.WriteLine($"[PYTHON]: {e.Data}");

            _pythonProcess.Start();
            _pythonProcess.BeginOutputReadLine();
            _pythonProcess.BeginErrorReadLine();
        }

        public static void StopEngine()
        {
            try
            {
                if (_pythonProcess != null && !_pythonProcess.HasExited)
                {
                    _pythonProcess.Kill(true);
                    _pythonProcess.Dispose();
                }
            }
            catch (Exception)
            {

            }
        }

    }
}
