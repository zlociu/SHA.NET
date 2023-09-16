namespace SHA.Algorithms;

using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public class Sha384 : Sha512
{
    public Sha384()
    {
        state = new();
        state.Init384();
    }

    protected override void InitState()
    {
        state.Init384();
    }

    public override int HashSizeBits => 384;
    public override int HashSizeBytes => 48;
    public override string Name => "SHA-384";

    public unsafe override string Hash => string.Format("0x{0:x16}{1:x16}{2:x16}{3:x16}{4:x16}{5:x16}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4], state.H[5], state.H[6]);
}