// using System.Text;
// using SHA.Algorithms;

// var sha = new Sha512();
// var bytes = Encoding.ASCII.GetBytes("krotki tekst, ktory sprawdzi szybkosc algorytmu");
// var s1 = new System.Diagnostics.Stopwatch();
// s1.Start();
// var arr = sha.ComputeHash(bytes);
// s1.Stop();
// Console.WriteLine($"{s1.ElapsedMilliseconds} ms");
// Console.WriteLine("0x" + string.Concat(arr.Select(x => string.Format("{0:x2}", x))));

// s1.Restart();
// sha.HashData(bytes);
// sha.HashFinal();
// s1.Stop();
// Console.WriteLine("{0} ms", s1.ElapsedMilliseconds);
// Console.WriteLine($"0x{sha.Hash}");