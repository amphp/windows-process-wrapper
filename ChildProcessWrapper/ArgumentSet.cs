using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace amphp.ChildProcessWrapper
{
    internal class ArgumentSet
    {
        private static readonly Regex ArgEscapeStep1Regex = new Regex(@"(\\*)""");
        private static readonly Regex ArgEscapeStep2Regex = new Regex(@"^(.*\s.*?)(\\*)$");

        private static readonly Dictionary<string, Action<ArgumentSet, string, string>> ArgumentParsers
            = new Dictionary<string, Action<ArgumentSet, string, string>>(3, StringComparer.InvariantCulture)
        {
            ["--address"] = ParseServerAddressArgument,
            ["--port"] = ParseServerPortArgument,
            ["--process-id"] = ParseProcessIDArgument,
            ["--cwd"] = ParseWorkingDirectoryArgument,
        };

        /// <summary>
        /// Encodes an argument for passing into a program, see https://stackoverflow.com/a/12364234/889949
        /// </summary>
        /// <param name="Input">The value that should be received by the program</param>
        /// <returns>The value which needs to be passed to the program for the original value 
        /// to come through</returns>
        public static string EscapeCommandLineArgument(string Input)
        {
            return !string.IsNullOrEmpty(Input)
                ? ArgEscapeStep2Regex.Replace(ArgEscapeStep1Regex.Replace(Input, @"$1\$0"), @"""$1$2$2""")
                : Input;
        }

        /// <summary>
        /// Parse the value supplied for the --port argument and validate it as a TCP port number
        /// </summary>
        /// <param name="ArgumentSet">The ArgumentSet instance in which the value should be stored</param>
        /// <param name="ArgName">The argument name</param>
        /// <param name="Value">The argument value</param>
        /// <exception cref="InvalidArgumentValueException"></exception>
        private static void ParseServerAddressArgument(ArgumentSet ArgumentSet, string ArgName, string Value)
        {
            if (ArgumentSet.ServerAddress != null) {
                throw new InvalidArgumentValueException($"{ArgName} argument specified more than once");
            }

            if (Value == null) {
                throw new InvalidArgumentValueException($"{ArgName} argument requires a value");
            }

            try {
                ArgumentSet.ServerAddress = IPAddress.Parse(Value);
            } catch (FormatException) {
                throw new InvalidArgumentValueException($"{Value} is not a valid IP address");
            }
        }

        /// <summary>
        /// Parse the value supplied for the --port argument and validate it as a TCP port number
        /// </summary>
        /// <param name="ArgumentSet">The ArgumentSet instance in which the value should be stored</param>
        /// <param name="ArgName">The argument name</param>
        /// <param name="Value">The argument value</param>
        /// <exception cref="InvalidArgumentValueException"></exception>
        private static void ParseServerPortArgument(ArgumentSet ArgumentSet, string ArgName, string Value)
        {
            if (ArgumentSet.ServerPort != 0) {
                throw new InvalidArgumentValueException($"{ArgName} argument specified more than once");
            }

            if (Value == null) {
                throw new InvalidArgumentValueException($"{ArgName} argument requires a value");
            }

            try {
                ArgumentSet.ServerPort = ushort.Parse(Value);
            } catch (OverflowException) {
                throw new InvalidArgumentValueException($"{Value} is not a valid TCP port number");
            } catch (FormatException) {
                throw new InvalidArgumentValueException($"{Value} is not a valid TCP port number");
            }

            if (ArgumentSet.ServerPort == 0) {
                throw new InvalidArgumentValueException($"{Value} is not a valid TCP port number");
            }
        }

        /// <summary>
        /// Parse the value supplied for the --process-id argument
        /// </summary>
        /// <param name="ArgumentSet">The ArgumentSet instance in which the value should be stored</param>
        /// <param name="ArgName">The argument name</param>
        /// <param name="Value">The argument value</param>
        /// <exception cref="InvalidArgumentValueException"></exception>
        private static void ParseProcessIDArgument(ArgumentSet ArgumentSet, string ArgName, string Value)
        {
            if (ArgumentSet.ProcessID != null) {
                throw new InvalidArgumentValueException($"{ArgName} argument specified more than once");
            }

            if (Value == null) {
                throw new InvalidArgumentValueException($"{ArgName} argument requires a value");
            }

            ArgumentSet.ProcessID = Value;
        }

        /// <summary>
        /// Parse the value supplied for the --cwd argument
        /// </summary>
        /// <param name="ArgumentSet">The ArgumentSet instance in which the value should be stored</param>
        /// <param name="ArgName">The argument name</param>
        /// <param name="Value">The argument value</param>
        /// <exception cref="InvalidArgumentValueException"></exception>
        private static void ParseWorkingDirectoryArgument(ArgumentSet ArgumentSet, string ArgName, string Value)
        {
            if (ArgumentSet.WorkingDirectory != null) {
                throw new InvalidArgumentValueException($"{ArgName} argument specified more than once");
            }

            if (Value == null) {
                throw new InvalidArgumentValueException($"{ArgName} argument requires a value");
            }

            ArgumentSet.WorkingDirectory = Value;
        }

        /// <summary>
        /// Parse a raw argument string array into an ArgumentSet instance
        /// </summary>
        /// <param name="Args">The raw argument string array</param>
        /// <returns>The parsed ArgumentSet instance</returns>
        /// <exception cref="InvalidArgumentException"></exception>
        /// <exception cref="InvalidArgumentValueException"></exception>
        public static ArgumentSet Parse(string[] Args)
        {
            var result = new ArgumentSet();
            var exeIndex = 0;

            foreach (var parts in Args.Select(Arg => Arg.Split('='))) {
                var name = parts[0];

                if (!ArgumentParsers.ContainsKey(name)) {
                    break;
                }

                var value = parts.Length > 1
                    ? string.Join("=", parts, 1, parts.Length  - 1)
                    : null;

                ArgumentParsers[name].Invoke(result, name, value);
                exeIndex++;
            }

            if (exeIndex >= Args.Length) {
                throw new InvalidArgumentException("No program supplied to execute");
            }

            if (result.ServerAddress == null) {
                result.ServerAddress = IPAddress.Loopback;
            }

            if (result.ServerPort == 0) {
                throw new InvalidArgumentException("A target port number is required");
            }

            if (result.ProcessID == null) {
                throw new InvalidArgumentException("A process ID string is required");
            }

            result.ExecutablePath = Args[exeIndex];
            result.Arguments = string.Join(" ", Args.Skip(exeIndex + 1).Select(EscapeCommandLineArgument).ToArray());

            return result;
        }

        /// <summary>
        /// The path of the program to execute
        /// </summary>
        public string ExecutablePath { get; private set; }

        /// <summary>
        /// The arguments to pass to the program
        /// </summary>
        public string Arguments { get; private set; }

        /// <summary>
        /// The working directory for the program
        /// </summary>
        public string WorkingDirectory { get; private set; }

        /// <summary>
        /// The IP address that should be used to connect to the parent server
        /// </summary>
        public IPAddress ServerAddress { get; private set; }

        /// <summary>
        /// The TCP port that should be used to connect to the parent server
        /// </summary>
        public int ServerPort { get; private set; }

        /// <summary>
        /// The process ID that should be used to identify the child to the parent
        /// </summary>
        public string ProcessID { get; private set; }
    }
}
