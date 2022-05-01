using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Benchmarking;

class Program
{
    private static void BenchmarkWindows()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            throw new UnsupportedPlatformException();

        string category = "Process";
        string processName = "dtls";

        PerformanceCounter cpuCounter = new PerformanceCounter(category, "% Processor Time", processName, true);
        PerformanceCounter ramCounter = new PerformanceCounter(category, "Private Bytes", processName, true);

        double cpuPercent;
        double ramKb;
        while (!Console.KeyAvailable)
        {
            cpuPercent = cpuCounter.NextValue() / Environment.ProcessorCount;
            ramKb = Math.Round(ramCounter.NextValue() / 1024, 2);
            Console.WriteLine($"{cpuPercent},{ramKb}");
            Thread.Sleep(16);
        }
    }
    
    public static void Main(string[] args)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            BenchmarkWindows();
        }
    }
}