public interface IHashAlgorithm
{
    void ComputeHash(ReadOnlySpan<byte> data);

    void ComputeHash(byte[] data);

    string GetHash();

    void ResetState();
}