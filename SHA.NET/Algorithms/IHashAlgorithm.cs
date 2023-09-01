public interface IHashAlgorithm
{
    void ComputeHash(ReadOnlySpan<byte> data);

    void ComputeHash(byte[] data);

    string Hash { get; }

    int HashSizeBits { get; }

    int HashSizeBytes { get; }
}