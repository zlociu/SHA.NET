
using System.Text;
using SHA.Algorithms;

var sha = new Sha512();
var bytes = File.ReadAllBytes("przykladowy_ndl.txt");
var s1 = new System.Diagnostics.Stopwatch();
s1.Start();
sha.ComputeHash("ABCDEFGHIJKLMNOPQRSTUVWXYZ"u8.ToArray());
s1.Stop();
Console.WriteLine("{0} ms", s1.ElapsedMilliseconds);
Console.WriteLine(sha.GetHash());
