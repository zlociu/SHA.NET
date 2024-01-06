namespace SHA.Algorithms;

using System.Runtime.CompilerServices;

public class Sha384 : Sha512
{
    public Sha384()
    {
        state = new();
        state.Init384();
        this.buffer = new byte[128];
        this.bufferLen = 0;
    }

    public override void Clear()
    {
        state.Init384();
        this.bufferLen = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected override unsafe byte[] GetHashByteArray(ulong* ptr)
    {
        var result = new byte[48];

        byte* bytePtr = (byte*)ptr;
        for(int i = 0; i < 48; i++) result[i] = bytePtr[i ^ 7];
        return result;
    }

    public override int HashSizeBits => 384;
    public override int HashSizeBytes => 48;
    public override string Name => "SHA-384";

    public unsafe override string Hash => string.Format("{0:x16}{1:x16}{2:x16}{3:x16}{4:x16}{5:x16}{6:x16}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4], state.H[5], state.H[6]);
}