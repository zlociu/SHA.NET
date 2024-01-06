namespace SHA.Algorithms;

public interface IHashAlgorithm
{
    byte[] ComputeHash(ReadOnlySpan<byte> data);
    byte[] ComputeHash(byte[] data);
    byte[] ComputeHash(Stream stream);

    void Clear();

    void HashData(ReadOnlySpan<byte> data);
    void HashData(byte[] data, int start, int size);
    void HashFinal();

    string Hash { get; }
    int HashSizeBits { get; }
    int HashSizeBytes { get; }
    string Name { get; }
}