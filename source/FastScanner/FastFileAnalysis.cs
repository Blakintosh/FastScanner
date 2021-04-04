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
    public static class FastFileAnalysis
    {
        /// <summary>
        /// Invalid Characters from C# Reference Source
        /// </summary>
        internal static readonly char[] InvalidPathChars =
        {
            '\"', '<', '>', '|', '\0',
            (char)1, (char)2, (char)3, (char)4, (char)5, (char)6, (char)7, (char)8, (char)9, (char)10,
            (char)11, (char)12, (char)13, (char)14, (char)15, (char)16, (char)17, (char)18, (char)19, (char)20,
            (char)21, (char)22, (char)23, (char)24, (char)25, (char)26, (char)27, (char)28, (char)29, (char)30,
            (char)31
        };

        /// <summary>
        /// Black Ops III Fast File Search Needle
        /// </summary>
        private static readonly byte[] NeedleBo3 = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        /// <summary>
        /// Registered processors we can use for file-specific analysis
        /// </summary>
        internal static Dictionary<string, Action<string, byte[]>> FileProcessors = new Dictionary<string, Action<string, byte[]>>
        {
            { ".lua", (string fileName, byte[] fileData)=>
            {
                LuaFile.Analyse(fileName, fileData);
            } },
            { ".gsc", (string fileName, byte[] fileData)=>
            {
                ScriptFile.Analyse(fileName, fileData);
            } },
            { ".csc", (string fileName, byte[] fileData)=>
            {
                ScriptFile.Analyse(fileName, fileData);
            } },
        };

        /// <summary>
        /// Scans a decompressed Black Ops III Fast File and runs any file-specific processors where applicable.
        /// </summary>
        internal static void ScanDecompressedFastFile(BinaryReader reader)
        {
            // Need to skip the strings and assets
            // to avoid redundant checks on these by
            // the scanner
            var stringCount = reader.ReadInt32();
            reader.BaseStream.Position = 32;
            var assetCount = reader.ReadInt32();

            reader.BaseStream.Position = 56 + (stringCount - 1) * 8;

            for (int i = 0; i < stringCount; i++)
            {
                reader.ReadNullTerminatedString();
            }

            reader.BaseStream.Position += 16 * assetCount;


            var results = new List<string>();
            var offsets = reader.FindBytes(NeedleBo3);

            foreach (var offset in offsets)
            {
                try
                {
                    reader.BaseStream.Position = offset;

                    var namePtr = reader.ReadUInt64();
                    var size = reader.ReadInt64();
                    var dataPtr = reader.ReadUInt64();

                    // Check the pointers
                    if (namePtr == 0xFFFFFFFFFFFFFFFF && dataPtr == 0xFFFFFFFFFFFFFFFF && size <= uint.MaxValue)
                    {
                        // Linker only allows names up to 127
                        var name = reader.ReadNullTerminatedString(128);

                        if (name.IndexOfAny(InvalidPathChars) < 0)
                        {
                            var extension = Path.GetExtension(name);

                            foreach(KeyValuePair<string, Action<string, byte[]>> processor in FileProcessors)
                            {
                                if( extension == processor.Key)
                                {
                                    processor.Value.Invoke(name, reader.ReadBytes((int)size));
                                    break;
                                }
                            }
                        }
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine(": ERROR: " + e);
                    continue;
                }
            }
        }
    }
}
