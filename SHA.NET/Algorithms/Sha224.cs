namespace SHA.Algorithms;

using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public class Sha224 : Sha256
{
    public Sha224()
    {
        state = new();
        state.Init224();
    }

    protected override void InitState()
    {
        state.Init224();
    }

    public override int HashSizeBits => 224;
    public override int HashSizeBytes => 28;

    public  unsafe override string Hash => string.Format("0x{0:x8}{1:x8}{2:x8}{3:x8}{4:x8}{5:x8}{6:x8}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4], state.H[5], state.H[6]);

}