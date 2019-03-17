using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;

namespace pubsuflist
{
    class Program
    {
        static void Main(string[] args)
        {
            var target = args[0];

            var wc = new WebClient();
            var tmp = Path.GetTempFileName();
            wc.DownloadFile("https://publicsuffix.org/list/public_suffix_list.dat", tmp);

            var domains = new List<string>();
            using (var fs = new FileStream(tmp, FileMode.Open))
            {
                using (var reader = new StreamReader(fs))
                {
                    string line;
                    do
                    {
                        line = reader.ReadLine();
                        if (line == null)
                            break;

                        if (line.StartsWith("/") || string.IsNullOrEmpty(line))
                            continue;

                        domains.Add(line);
                    } while (true);
                }
            }
            File.Delete(tmp);

            if (domains.Count() != domains.Distinct().Count())
            {
                Console.WriteLine("Contains duplicates");
            }

            var crcs = new List<ulong>();
            foreach (var domain in domains)
            {
                var hash = Crc64.Compute(0, Encoding.ASCII.GetBytes(domain));
                if (crcs.Contains(hash))
                {
                    Console.WriteLine(domain);
                }
                else
                {
                    crcs.Add(hash);
                }
            }

            if (crcs.Count() != crcs.Distinct().Count())
            {
                Console.WriteLine($"Contains {crcs.Count() - crcs.Distinct().Count()} out of {crcs.Count()} duplicates");
            }

            crcs.Sort();

            using (var fs2 = new FileStream(target, FileMode.Create))
            {
                foreach (var crc in crcs)
                {
                    var bytes = BitConverter.GetBytes(crc);
                    fs2.Write(bytes, 0, bytes.Length);
                }
            }
        }
    }
}
