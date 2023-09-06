using SHA.Algorithms;

internal class Program
{
    private static void ParseCmdArguments(string[] args)
    {
        
    }

    private static void Main(string[] args)
    {
        var sha = new Sha256();
        var bytes = File.ReadAllBytes("przykladowy_ndl.txt");
        var s1 = new System.Diagnostics.Stopwatch();
        s1.Start();
        sha.ComputeHash(bytes);
        s1.Stop();
        Console.WriteLine("{0} ms", s1.ElapsedMilliseconds);
        Console.WriteLine(sha.Hash);

        using var stream = File.OpenRead("przykladowy_ndl.txt");
        s1.Restart();
        sha.ComputeHash(stream);
        s1.Stop();
        Console.WriteLine("{0} ms", s1.ElapsedMilliseconds);
        Console.WriteLine(sha.Hash);
    }
}