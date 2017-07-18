using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace amphp.ChildProcessWrapper
{
    internal static class Program
    {
        private const int READ_CHUNK_SIZE = 1024;

        private static readonly Regex ArgEscapeStep1Regex = new Regex("(\\\\*)\"");
        private static readonly Regex ArgEscapeStep2Regex = new Regex(@"^(.*\s.*?)(\\*)$");

        private static readonly List<TcpClient> Sockets = new List<TcpClient>(3)
        {
            new TcpClient(), new TcpClient(), new TcpClient()
        };

        private static readonly Dictionary<int, TcpClient> PendingConnectSockets = new Dictionary<int, TcpClient>(3)
        {
            [0] = Sockets[0],
            [1] = Sockets[1],
            [2] = Sockets[2],
        };

        private static readonly Semaphore ConnectSemaphore = new Semaphore(0, 1);
        private static readonly Semaphore ProcessStartSemaphore = new Semaphore(0, 1);

        private static ArgumentSet _args;
        private static Process _process;

        /// <summary>
        /// Encodes an argument for passing into a program, see https://stackoverflow.com/a/12364234/889949
        /// </summary>
        /// <param name="Input">The value that should be received by the program</param>
        /// <returns>The value which needs to be passed to the program for the original value 
        /// to come through</returns>
        public static string EncodeParameterArgument(string Input)
        {
            return !string.IsNullOrEmpty(Input)
                ? ArgEscapeStep2Regex.Replace(ArgEscapeStep1Regex.Replace(Input, @"$1\$0"), "\"$1$2$2\"")
                : Input;
        }

        private static void ConnectCallback(IAsyncResult Result)
        {
            bool finished;
            var id = (int)Result.AsyncState;

            ConfigureSocket(id);

            lock (PendingConnectSockets) {
                PendingConnectSockets.Remove(id);
                finished = PendingConnectSockets.Count == 0;
            }

            if (finished) {
                ConnectSemaphore.Release();
            }
        }

        private static void ConfigureSocket(int ID)
        {
            var stream = Sockets[ID].GetStream();
            var bytes = Encoding.ASCII.GetBytes($"{ID};{_args.ProcessID}\n");

            stream.Write(bytes, 0, bytes.Length);
            var len = stream.Read(bytes, 0, 2);

            if (len != 2 || bytes[0] != 0 || bytes[1] != 10) {
                throw new Exception("Weirdo shit is happening");
            }

            switch (ID) {
                case 0:
                    new Thread(PassThroughStdInData).Start();
                    break;

                case 1:
                    new Thread(PassThroughStdOutData).Start();
                    break;

                case 2:
                    new Thread(PassThroughStdErrData).Start();
                    break;
            }
        }

        private static void CopyTo(this BinaryReader Reader, BinaryWriter Writer)
        {
            var buffer = new byte[READ_CHUNK_SIZE];
            int count;

            do {
                count = Reader.Read(buffer, 0, READ_CHUNK_SIZE);
                Writer.Write(buffer, 0, count);
            } while (count > 0);
        }

        private static void PassThroughStdInData()
        {
            ProcessStartSemaphore.WaitOne();
            ProcessStartSemaphore.Release();

            using (var writer = new BinaryWriter(_process.StandardInput.BaseStream))
            using (var reader = new BinaryReader(Sockets[0].GetStream())) {
                reader.CopyTo(writer);
            }
        }

        private static void PassThroughStdOutData()
        {
            ProcessStartSemaphore.WaitOne();
            ProcessStartSemaphore.Release();

            using (var writer = new BinaryWriter(Sockets[1].GetStream()))
            using (var reader = new BinaryReader(_process.StandardOutput.BaseStream)) {
                reader.CopyTo(writer);
            }

            Sockets[1].Close();
        }

        private static void PassThroughStdErrData()
        {
            ProcessStartSemaphore.WaitOne();
            ProcessStartSemaphore.Release();

            using (var writer = new BinaryWriter(Sockets[2].GetStream()))
            using (var reader = new BinaryReader(_process.StandardError.BaseStream)) {
                reader.CopyTo(writer);
            }

            Sockets[2].Close();
        }

        private static void Main(string[] Args)
        {
            try {
                _args = ArgumentSet.Parse(Args);
            } catch (InvalidArgumentException e) {
                Console.Error.WriteLine(e.Message);
                Environment.Exit(-1);
            }

            for (var i = 0; i < Sockets.Count; i++) {
                Sockets[i].BeginConnect(_args.ServerAddress, _args.ServerPort, ConnectCallback, i);
            }

            _process = new Process
            {
                StartInfo = {
                    FileName = _args.ExecutablePath,
                    Arguments = _args.Arguments,
                    WorkingDirectory = _args.WorkingDirectory,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
            };

            ConnectSemaphore.WaitOne();
            ConnectSemaphore.Close();

            _process.Start();

            ProcessStartSemaphore.Release();

            _process.WaitForExit();

            Environment.Exit(_process.ExitCode);
        }
    }
}
