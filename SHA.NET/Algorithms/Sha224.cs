namespace SHA.Algorithms;

using System.Runtime.CompilerServices;

public class Sha224 : Sha256
{
    public Sha224()
    {
        this.state = new();
        this.state.Init224();
    }

    public override void Clear()
    {
        this.state.Init224();
        this.bufferLen = 0;
    }

    public override int HashSizeBits => 224;
    public override int HashSizeBytes => 28;
    public override string Name => "SHA-224";

    public unsafe override string Hash => string.Format("{0:x8}{1:x8}{2:x8}{3:x8}{4:x8}{5:x8}{6:x8}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4], state.H[5], state.H[6]);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected override unsafe byte[] GetHashByteArray(uint* ptr)
    {
        var result = new byte[28];

        byte* bytePtr = (byte*)ptr;
        for(int i = 0; i < 28; i++) result[i] = bytePtr[i ^ 3];
        return result;
    }
}