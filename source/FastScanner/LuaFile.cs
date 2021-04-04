using System;
using System.Collections.Generic;
using System.IO;
using PhilLibX.IO;
using System.Security.Cryptography;
using System.IO.Compression;

/*
 * Based on Cerberus.Logic (Credit: Scobalula)
 * Source: https://github.com/Scobalula/Cerberus-Repo/blob/master/Cerberus.Logic/FastFile.cs
*/

namespace FastScanner
{
    public static class LuaFile
    {
        /// <summary>
        /// Function pointers that will throw a red alert.
        /// </summary>
        private static readonly Dictionary<string, string> RedFunctions = new Dictionary<string, string>()
        {
            { "io.popen", "Can be used to contact a server without player knowledge, and can be used to log IPs and other sensitive data." },
            { "os.execute", "Used to execute commands on the user's shell." },
            { "os.getenv", "Grabs an environment variable. Could be used to get sensitive data." },
        };

        /// <summary>
        /// Function pointers that will throw an amber alert.
        /// </summary>
        private static readonly Dictionary<string, string> AmberFunctions = new Dictionary<string, string>()
        {
            { "io.open", "Likely to just be in use for data saving (such as progression), but can be used for other purposes." },
            { "io.write", "Used to write to a file on user's PC." },
            { "os.remove", "Used to delete files/folders. Might be to manage a progression file, but could be used for worse purposes." },
            { "Engine.OpenURL", "Generally used for benign purposes (e.g. opening a Discord link), but could be used to open things such as malicious websites" },
            { "Engine.GetXUID", "Map/mod is checking user XUIDs. This could be used to target specific players with certain code. This is unlikely though, this might just be a false positive from Treyarch's existing code." },
            { "Engine.GetXUID64", "Map/mod is checking user XUIDs. This could be used to target specific players with certain code. This is unlikely though, this might just be a false positive from Treyarch's existing code." }
        };

        /// <summary>
        /// Checks whether a function call exists in a given string
        /// </summary>
        private static bool CheckForFunctionCall(KeyValuePair<string, string> functionCall, string givenString, string nextString)
        {
            string[] splitFunction = functionCall.Key.Split('.');

            if (givenString == splitFunction[0])
            {
                if (splitFunction.Length > 1 && nextString != splitFunction[1])
                {
                    return false;
                }
                return true;
            }
            return false;
        }

        /// <summary>
        /// Analyses given byte code from a Lua file.
        /// </summary>
        internal static void Analyse(string fileName, byte[] fileData)
        {
            // This is a fairly basic method of reading through all the strings of a Lua file to check for function calls, but it should be adequate for finding functions
            MemoryStream byteStream = new MemoryStream(fileData);

            StreamReader reader = new StreamReader(byteStream, System.Text.Encoding.UTF8, true);

            var stringArray = reader.ReadToEnd().Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries);

            for (int i = 0; i < stringArray.Length; i++)
            {
                foreach (KeyValuePair<string, string> redFunction in RedFunctions)
                {
                    if (i + 2 < stringArray.Length)
                    {
                        // i + 1 is a bit of data related to the initial function that I don't need to worry about
                        bool exists = CheckForFunctionCall(redFunction, stringArray[i], stringArray[i + 2]);

                        if (exists)
                        {
                            Program.RedWarnings.Add("Function " + redFunction.Key + " Found in: " + fileName + " : " + redFunction.Value);
                            break;
                        }
                    }
                }
            }

            for (int i = 0; i < stringArray.Length; i++)
            {
                foreach (KeyValuePair<string, string> amberFunction in AmberFunctions)
                {
                    if (i + 2 < stringArray.Length)
                    {
                        bool exists = CheckForFunctionCall(amberFunction, stringArray[i], stringArray[i + 2]);

                        if (exists)
                        {
                            Program.AmberWarnings.Add("Function " + amberFunction.Key + " Found in: " + fileName + " : " + amberFunction.Value);
                            break;
                        }
                    }
                }
            }
        }
    }
}
