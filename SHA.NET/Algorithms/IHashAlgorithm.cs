public interface IHashAlgorithm
{
    void ComputeHash(ReadOnlySpan<byte> data);

    void ComputeHash(byte[] data);

    void ComputeHash(Stream stream);

    string Hash { get; }

    int HashSizeBits { get; }

    int HashSizeBytes { get; }

    string Name { get; }
}