using SHA.Algorithms;

internal class Program
{
    private static void Main(string[] args)
    {
        IHashAlgorithm sha = args[0] switch
        {
            "SHA1" => new Sha1(),
            "SHA224" => new Sha224(),
            "SHA256" => new Sha256(),
            "SHA384" => new Sha384(),
            "SHA512" => new Sha512(),
            _ => throw new ArgumentException("Invalid algorithm name. Available algorithms: SHA1, SHA224, SHA256, SHA384, SHA512")
        };

        Console.WriteLine(args[1]);

        using var stream = File.OpenRead(args[1]);
        var s1 = new System.Diagnostics.Stopwatch();
        s1.Start();
        sha.ComputeHash(stream);
        s1.Stop();
        Console.WriteLine("\n{0} ms", s1.ElapsedMilliseconds);
        Console.WriteLine("{0}: {1}", sha.Name, sha.Hash);

        Console.ReadKey();
    }
}