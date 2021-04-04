using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;

/*
 * FastScanner v1.0
 * Made by Blak & Scobalula
*/

namespace FastScanner
{
    class Program
    {

        /// <summary>
        /// Expected file types within a map/mod Workshop folder. All those that aren't these, but aren't Suspect either, will be amber flagged.
        /// </summary>
        static readonly string[] ExpectedFiles =
        {
            ".ff",
            ".xpak",
            ".json",
            ".mkv",
            ".sabl",
            ".sabs",
            ".png",
            ".jpg",
#if DEBUG //In Debug mode, the program does not delete the decompressed FFs, so let's add this redundancy
            ".output",
#endif
        };

        /// <summary>
        /// Suspect file types within a map/mod Workshop folder. All files of these types will be red flagged.
        /// </summary>
        static readonly string[] DangerousFiles =
        {
            ".exe",
            ".dll",
            ".bat",
            ".iso",
            ".dif",
            ".com",
        };

        /// <summary>
        /// List to store amber warnings
        /// </summary>
        public static List<string> AmberWarnings = new List<string>();

        /// <summary>
        /// List to store red alerts
        /// </summary>
        public static List<string> RedWarnings = new List<string>();

        /// <summary>
        /// Command Line Options
        /// </summary>
        static CliOptions Options { get; set; }

        /// <summary>
        /// Class to hold CLI options
        /// </summary>
        class CliOptions
        {
            [Option('v', "verbose", Required = false, HelpText = "Outputs more information to the console.")]
            public bool Verbose { get; set; }
            [Option('h', "help", Required = false, HelpText = "Prints this message.")]
            public bool Help { get; set; }
        }

        /// <summary>
        /// Prints a message in verbose mode
        /// </summary>
        static void PrintVerbose(object value)
        {
            if (Options?.Verbose == true)
            {
                Console.WriteLine(value);
            }
        }

        /// <summary>
        /// Prints help output
        /// </summary>
        static void PrintHelp(ParserResult<CliOptions> outputOptions)
        {
            var helpText = new HelpText
            {
                AdditionalNewLineAfterOption = false,
                AddDashesToOption = true,
            };

            helpText.AddOptions(outputOptions);

            var stuff = helpText.ToString().Split('\n').Where(x => !string.IsNullOrWhiteSpace(x));

            Console.WriteLine(": Example: FastScanner [options] <folders>");
            Console.WriteLine(": Options: ");

            foreach (var item in stuff)
            {
                Console.WriteLine(":\t{0}", item.Trim());
            }
        }

        /// <summary>
        /// Processes a Steam Workshop map/mod folder
        /// </summary>
        /// <param name="dirPath"></param>
        static void ProcessWorkshopFolder(string dirPath)
        {
            if (Directory.Exists(dirPath))
            {
                //filesProcessed++;
                Console.WriteLine(": Processing {0}...", (dirPath));

                // Main sources of malicious content will be stored within scripts & LUA files that are inside an item's FFs.
                foreach(var FFfile in Directory.GetFiles(dirPath, "*.ff"))
                {
                    PrintVerbose(": Decompressing and Processing Fast File.....");

                    //Skip ZM Temple, it causes issues due to a weird large number
                    //of blocks
                    if (Path.GetFileName(FFfile) != "zm_temple")
                    {
                        try
                        {
                            FastFile.Decompress(FFfile, FFfile + ".output");

                            // Run logic to analyse
                            using (var reader = new BinaryReader(File.OpenRead(FFfile + ".output")))
                            {
                                FastFileAnalysis.ScanDecompressedFastFile(reader);
                            }
                        }
                        catch (Exception e)
                        {
                            PrintVerbose(e);
                            throw e;
                        }
                        finally
                        {
#if !DEBUG
                                                        File.Delete(FFfile + ".output");
#endif
                        }
                    }

                    //break;
                }

                // But we also need to scan for other "unexpected" files. We might get a hint of a hidden virus, etc, from this.
                foreach(var file in Directory.GetFiles(dirPath, "*.*", SearchOption.AllDirectories))
                {
                    string FileExtension = Path.GetExtension(file);
                    bool Found = false;

                    // Check the extension of this file against our known "normal" files.
                    foreach(var extension in ExpectedFiles)
                    {
                        if(FileExtension == extension)
                        {
                            Found = true;
                            // safe (probably)
                            break;
                        }
                    }

                    // Check the extension of this file against suspicious file extensions.
                    foreach(var extension in DangerousFiles)
                    {
                        if(FileExtension == extension)
                        {
                            Found = true;
                            Program.RedWarnings.Add("File with known potentially harmful extension: "+Path.GetFileName(file));
                            break;
                        }
                    }

                    // If neither of the above found anything, we'll log an unrecognized file.
                    if(!Found)
                    {
                        //log an amber alert
                        Program.AmberWarnings.Add("File with an extension you wouldn't normally expect: " + Path.GetFileName(file));
                    }
                }

                Console.WriteLine(": Processed {0} successfully.", Path.GetFileName(dirPath));
            }
        }

        /// <summary>
        /// Main Entry Point
        /// </summary>
        static void Main(string[] args)
        {
            Console.WriteLine(": ----------------------------------------------------------");
            Console.WriteLine(": FastScanner - Black Ops III FastFile Checker");
            Console.WriteLine(": Developed by Blak & Scobalula");
            Console.WriteLine(": Version: {0}", Assembly.GetExecutingAssembly().GetName().Version);
            Console.WriteLine(": ----------------------------------------------------------");

            var parser = new Parser(config => config.HelpWriter = null);
            var cliOptions = parser.ParseArguments<CliOptions>(args).WithParsed(x => Options = x).WithNotParsed(_ => Options = new CliOptions());

            var filesProcessed = 0;

            // Force working directory back to exe
            Directory.SetCurrentDirectory(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));

            Console.WriteLine(": Exporting to: {0}", Directory.GetCurrentDirectory());

            var GameLocation = Environment.GetEnvironmentVariable("TA_GAME_PATH");
            if( GameLocation == null )
            {
                Console.WriteLine(": WARNING: Can't find your Black Ops III install. You'll need to drag Workshop map/mod folders on manually.");
            }

            if(args.Length > 0)
            {
                foreach (var arg in args)
                {
                    try
                    {
                        ProcessWorkshopFolder(arg);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(": An error has occured while processing {0}: {1}", Path.GetDirectoryName(arg), e.Message);
                        PrintVerbose(e);
                    }
                }
            }
            else if(GameLocation != null)
            {
                var WorkshopDirectory = Path.GetFullPath(GameLocation + "/../../workshop/content/311210");
                Console.WriteLine(": WARNING: No Workshop folder provided. Provide Steam link to desired Workshop item (you must already have it installed):");
                // TFC = https://steamcommunity.com/sharedfiles/filedetails/?id=1793032002
                var WorkshopLink = Console.ReadLine();

                var WorkshopURLitems = WorkshopLink.Split('?', '&');
                string WorkshopID = "";
                for(var i = 0; i < WorkshopURLitems.Length; i++)
                {
                    if(WorkshopURLitems[i].Contains("id"))
                    {
                        WorkshopID = WorkshopURLitems[i].Split('=')[1];
                    }
                }

                Console.WriteLine(": Workshop ID for item found: " + WorkshopID +". Checking whether it's installed...");

                var ExpectedDirectory = Path.Combine(WorkshopDirectory, WorkshopID);
                if(!Directory.Exists(ExpectedDirectory))
                {
                    Console.WriteLine(": ERROR: Workshop item not found in " + ExpectedDirectory + ". Check you've got the item installed, or drag the workshop folder for the item directly onto this program executable.");
                }
                else
                {
                    ProcessWorkshopFolder(ExpectedDirectory);
                }
            }
            

            if (Options.Help || filesProcessed <= 0)
            {
                PrintHelp(cliOptions);
            }

            GC.Collect();

            Console.WriteLine(": ----------------------------------------------------------");
            Console.WriteLine(": Report");

            Console.WriteLine(": FastScanner found " + Program.RedWarnings.Count + " Red Alerts, and " + Program.AmberWarnings.Count + " Amber Alerts.");

            // Report on what's been found
            if (Program.RedWarnings.Count > 0)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Red;

                Console.WriteLine(": Red Alerts:");

                foreach(string warning in Program.RedWarnings)
                {
                    Console.WriteLine("* " + warning);
                }

                if(Program.AmberWarnings.Count > 0)
                {
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Yellow;

                    Console.WriteLine(": Amber Alerts:");

                    foreach (string warning in Program.AmberWarnings)
                    {
                        Console.WriteLine("* " + warning);
                    }
                }

                Console.BackgroundColor = ConsoleColor.Red;
                Console.ForegroundColor = ConsoleColor.White;

                Console.WriteLine(": On the basis of these warnings it is strongly advised that you exercise extreme caution before launching the map/mod. You should seek an explanation from the Workshop item author for what they are doing, and you should trust their explanation before then running their map/mod.");
            }
            else if (Program.AmberWarnings.Count > 0)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Yellow;

                Console.WriteLine(": Amber Alerts:");

                foreach (string warning in Program.AmberWarnings)
                {
                    Console.WriteLine("* " + warning);
                }

                Console.BackgroundColor = ConsoleColor.Yellow;
                Console.ForegroundColor = ConsoleColor.Black;

                Console.WriteLine(": On the basis of these warnings it is advised that you should have a level of caution before launching the map/mod, but in most instances it is probably still safe to run. If you have any doubts, you should seek an explanation from the author.");
            }
            else
            {
                Console.BackgroundColor = ConsoleColor.Green;
                Console.ForegroundColor = ConsoleColor.Black;

                Console.WriteLine(": The program did not detect any potentially malicious content. This however is not an 100% guarantee that the map/mod is safe to play, and the program cannot be held liable for any false negatives.");
            }

            Console.ResetColor();

            Console.WriteLine(": Execution completed successfully, press Enter to exit.");
            Console.ReadLine();
        }
    }
}