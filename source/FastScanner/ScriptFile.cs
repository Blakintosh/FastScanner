using System;
using System.Collections.Generic;
using System.IO;
using PhilLibX.IO;
using System.Security.Cryptography;
using System.IO.Compression;
using System.Text;

/*
 * Based on Cerberus.Logic (Credit: Scobalula)
 * Source: https://github.com/Scobalula/Cerberus-Repo/blob/master/Cerberus.Logic/FastFile.cs
*/

namespace FastScanner
{
    public static class ScriptFile
    {
        /// <summary>
        /// Function pointers that will throw a red alert.
        /// </summary>
        // Specify functions in lowercase, the code will lowercase function output to compare
        private static readonly Dictionary<string, string> RedFunctions = new Dictionary<string, string>()
        {
            { "getipaddress", "IP grabbing a player." },
        };

        /// <summary>
        /// Function pointers that will throw an amber alert.
        /// </summary>
        private static readonly Dictionary<string, string> AmberFunctions = new Dictionary<string, string>()
        {
            { "getxuid", "Map/mod is checking user XUIDs. This could be used to target specific players with certain code." },
        };

        /// <summary>
        /// Generates a Bo3-friendly FNV-1A 32 bit hash
        /// </summary>
        private static UInt32 GSCRHash(string data)
        {
            UInt32 Result = 0x4B9ACE2F;

            List<byte> byteArray = new List<byte>();

            foreach(byte chunki in Encoding.ASCII.GetBytes(data))
            {
                byteArray.Add(chunki);
            }

            byteArray.Add(0x00);

            for (int i = 0; i < byteArray.Count; i++)
                Result = 0x1000193 * (byteArray[i] ^ Result);

            return Result;
        }

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
            // This is a fairly basic method of reading through all the integer hashes of a *SC file to check for function calls, but it should be adequate for finding functions
            // GSC aligns its hashes so we can do this...
            MemoryStream byteStream = new MemoryStream(fileData);

            BinaryReader reader = new BinaryReader(byteStream);

            while(reader.BaseStream.Position + 3 < reader.BaseStream.Length )
            {
                UInt32 value = reader.ReadUInt32();

                foreach (KeyValuePair<string, string> redFunction in RedFunctions)
                {
                    UInt32 stringHash = GSCRHash(redFunction.Key);

                    if (stringHash == value)
                    {
                        Program.RedWarnings.Add("Function " + redFunction.Key + " Found in: " + fileName + " : " + redFunction.Value);
                        break;
                    }
                }

                foreach (KeyValuePair<string, string> amberFunction in AmberFunctions)
                {
                    UInt32 stringHash = GSCRHash(amberFunction.Key);

                    if (stringHash == value)
                    {
                        Program.AmberWarnings.Add("Function " + amberFunction.Key + " Found in: " + fileName + " : " + amberFunction.Value);
                        break;
                    }
                }
            }
        }
    }
}
