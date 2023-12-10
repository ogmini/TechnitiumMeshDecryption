using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using TechnitiumLibrary.Security.Cryptography;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Tor;

using MeshCore;
using MeshCore.Message;
using CsvHelper;
using System.Globalization;
using CommandLine;

namespace MeshDecryptionTool
{
    internal class Program
    {
        private static string _password;
        private static string _profileFolder;
        private static string _profileFile;
        private static string _outputFolder;
        private static string _ticks;

        public class Options
        {
            [Option('p', "Password", Required = true, HelpText = "Provide profile password")]
            public string password { get { return _password; } set { _password = value; } }

            [Option('r', "Profile Name", Required = true, HelpText = "Provide name of profile")]
            public string profile {  get { return Path.GetFileNameWithoutExtension(_profileFile); } set { _profileFile = value + ".profile"; } }

            [Option('l', "Path to profile files", Required = true, HelpText = "Path to profile files")]
            public string profilefolder { get { return _profileFolder; } set { _profileFolder = value; } }
        }
        static void Main(string[] args)
        {
            _outputFolder = "Output\\";

            Console.WriteLine("Attempting Decryption");

            Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
            {
                Directory.CreateDirectory(_outputFolder);

                ParseProfileFile();
            });

            Console.WriteLine("Decryption successful with password - " + _password);
        }


        static void ParseProfileFile()
        {
            _ticks = DateTime.Now.Ticks.ToString();

            using (FileStream pFile = new FileStream(_profileFolder + _profileFile, FileMode.Open, FileAccess.Read))
            {
                MeshNode node = new MeshNode(pFile, _password, _profileFolder);
                string pStream = "Profile - " + node.UserId + " - " + _ticks + ".txt";
                using (StreamWriter wr = new StreamWriter(_outputFolder + pStream, false))
                {
                    wr.WriteLine("---Profile Details---");
                    wr.WriteLine("Profile Name: " + Path.GetFileNameWithoutExtension(_profileFile));
                    wr.WriteLine("Version: " + node.Version.ToString());
                    wr.WriteLine("Node Type: " + node.Type.ToString());
                    wr.WriteLine("Private Key: " + string.Join(", ", node.PrivateKey));
                    wr.WriteLine("Ciphers: " + node.SupportedCiphers.ToString());
                    wr.WriteLine("UserID: " + node.UserId);
                    wr.WriteLine("Local Service Port: " + node.LocalServicePort);
                    wr.WriteLine("Download Folder: " + node.DownloadFolder);
                    wr.WriteLine("Date Modified: " + node.ProfileDateModified);
                    wr.WriteLine("Displayname: " + node.ProfileDisplayName);
                    wr.WriteLine("Status: " + node.ProfileStatus.ToString());
                    wr.WriteLine("Status Message: " + node.ProfileStatusMessage);
                    wr.WriteLine("Image Modified: " + node.ProfileDisplayImageDateModified.ToString());
                    wr.WriteLine("Image: " + string.Join(", ", node.ProfileDisplayImage));
                    wr.WriteLine("Enable PNP: " + node.EnableUPnP.ToString());
                    wr.WriteLine("Allow Inbound: " + node.AllowInboundInvitations.ToString());
                    wr.WriteLine("Only Local: " + node.AllowOnlyLocalInboundInvitations.ToString());
                    wr.WriteLine("AppData: " + string.Join(", ", node.AppData));
                    wr.WriteLine("Network Count: " + node.Networks.Count.ToString());

                    if (node.ProfileDisplayImage.Length > 0)
                    {
                        File.WriteAllBytes(_outputFolder + "Profile - " + node.UserId + " - Profile Image - " + _ticks + ".jpg", node.ProfileDisplayImage);
                    }

                    wr.WriteLine("---Proxy Details---");
                    if (node.Proxy == null)
                    {
                        wr.WriteLine("NO Proxy");
                    }
                    else
                    {
                        wr.WriteLine("Proxy Type: " + node.Proxy.Type.ToString());
                        wr.WriteLine("Proxy Address: " + node.Proxy.Address);
                        wr.WriteLine("Proxy Port: " + node.Proxy.Port.ToString());
                        wr.WriteLine("Proxy Domain: " + node.Proxy.Credential.Domain);
                        wr.WriteLine("Proxy Username: " + node.Proxy.Credential.UserName);
                        wr.WriteLine("Proxy Password: " + node.Proxy.Credential.Password);
                    }

                    foreach (var n in node.Networks)
                    {
                        string nStream = n.Value.NetworkName + " - " + _ticks + ".txt";
                        using (StreamWriter wrn = new StreamWriter(_outputFolder + nStream, false))
                        {
                            wrn.WriteLine("Network ID: " + n.Key.ToString());
                            wrn.WriteLine("Metwork Type: " + n.Value.Type.ToString());
                            wrn.WriteLine("Network Name: " + n.Value.NetworkName);
                            wrn.WriteLine("Shared Secret: " + n.Value.SharedSecret);
                            wrn.WriteLine("Message Store ID: " + n.Value.GetMessageStoreID());
                            wrn.WriteLine("Group Display Image: " + string.Join(", ", n.Value.GroupDisplayImage));

                            if (n.Value.GroupDisplayImage.Length > 0)
                            {
                                File.WriteAllBytes(_outputFolder + n.Value.NetworkName + " - Group Image - " + _ticks + ".jpg", n.Value.GroupDisplayImage);
                            }
                            
                        }

                        string npStream = n.Value.NetworkName + " - Peers - " + _ticks + ".txt";
                        using (StreamWriter wrnp = new StreamWriter(_outputFolder + npStream, false))
                        {
                            wrnp.WriteLine("Client");
                            var self = n.Value.SelfPeer;
                            wrnp.WriteLine(self.PeerUserId + " - " + node.ProfileDisplayName);

                            wrnp.WriteLine("----------------------");

                            wrnp.WriteLine("Other Known Peers");
                            var knownPeers = n.Value.PeersKnown;
                            foreach (var k in knownPeers) 
                            {
                                wrnp.WriteLine(k.PeerUserId + " - " + k.PeerDisplayName);
                            }          
                        }

                        string mcStream = n.Value.NetworkName + " - Messages - " + n.Value.GetMessageStoreID() + " - " + _ticks + ".csv";
                        using (var writer = new StreamWriter(_outputFolder + mcStream, false))
                        {
                            using (var csv = new CsvWriter(writer, CultureInfo.InvariantCulture))
                            {
                                int x = n.Value.GetMessageCount();
                                csv.WriteRecords(n.Value.GetLatestMessages(x, x));

                                foreach (var m in n.Value.GetLatestMessages(x, x))
                                {
                                    string rcStream = n.Value.NetworkName + " - Message Recipients - " + m.MessageNumber + " - " + n.Value.GetMessageStoreID() + " - " + _ticks + ".csv";
                                    using (var wrc = new StreamWriter(_outputFolder + rcStream, false))
                                    {
                                        using (var csvr = new CsvWriter(wrc, CultureInfo.InvariantCulture))
                                        {
                                            csvr.WriteRecords(m.Recipients);
                                        }
                                    }
                                }
                            }
                        }                       
                    } 
                }
            }
        }
    }
}
