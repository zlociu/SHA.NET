namespace SHA.Algorithms;

using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public class Sha1: IHashAlgorithm
{
    struct SHA1State
    {
        public unsafe fixed uint H[5];

        public unsafe SHA1State()
        {
            this.H[0] = 0x67452301u;
            this.H[1] = 0xefcdab89u;
            this.H[2] = 0x98badcfeu;
            this.H[3] = 0x10325476u;
            this.H[4] = 0xc3d2e1f0u;
        }       
    }

    private SHA1State state;

    public Sha1()
    {
        this.state = new();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private uint F(uint x, uint y, uint z)
    {
        return (x & y) | ((~x) & z);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private uint G(uint x, uint y, uint z)
    {
        return (x & y) | (x & z) | (y & z);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private uint H(uint x, uint y, uint z)
    {
        return x ^ y ^ z;
    }

    public unsafe void ComputeHash(ReadOnlySpan<byte> data)
    {
        this.state = new();

        fixed (SHA1State* statePtr = &this.state)
        {
            if (data.Length == 0)
            {
                this.ComputeHashUnsafe(null, 0, statePtr);
                return;
            }

            fixed (byte* ptr = &MemoryMarshal.GetReference(data))
            {
                this.ComputeHashUnsafe(ptr, data.Length, statePtr);
            }
        }
        
    }

    public unsafe void ComputeHash(byte[] data)
    {
        this.state = new();

        fixed (SHA1State* statePtr = &this.state)
        {
            if (data is null || data.Length == 0)
            {
                this.ComputeHashUnsafe(null, 0, statePtr);
                return;
            }

            fixed (byte* ptr = &data[0])
            {
                this.ComputeHashUnsafe(ptr, data.Length, statePtr);
            }
        }
    }

    public unsafe string Hash => string.Format("0x{0:x8}{1:x8}{2:x8}{3:x8}{4:x8}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4]);

    public int HashSizeBits => 160;
    public int HashSizeBytes => 20;

    private unsafe void ComputeInternal(SHA1State* state, byte* data)
    {
        uint A = state->H[0];
        uint B = state->H[1];
        uint C = state->H[2];
        uint D = state->H[3];
        uint E = state->H[4];

        uint[] buffer = ArrayPool<uint>.Shared.Rent(80);
        byte* offsetPtr = data;
        int k = 0;
        while (k < 16)
        {
            buffer[k] =
                (((uint)offsetPtr[(k * 4) + 0]) << 24) +
                (((uint)offsetPtr[(k * 4) + 1]) << 16) +
                (((uint)offsetPtr[(k * 4) + 2]) << 8) +
                (((uint)offsetPtr[(k * 4) + 3]) << 0);

            k++;
        }

        while (k < 80)
        {
            buffer[k] = BitOperations.RotateLeft(buffer[k - 3] ^ buffer[k - 8] ^ buffer[k - 14] ^ buffer[k - 16], 1);
            k++;
        }

        uint tmp = 0;
        short round = 0;
        while (round < 20)
        {
            tmp = BitOperations.RotateLeft(A, 5) + F(B, C, D) + E + 0x5a827999u + buffer[round];
            E = D;
            D = C;
            C = BitOperations.RotateLeft(B, 30);
            B = A;
            A = tmp;

            round++;
        }

        while (round < 40)
        {
            tmp = BitOperations.RotateLeft(A, 5) + H(B, C, D) + E + 0x6ed9eba1u + buffer[round];
            E = D;
            D = C;
            C = BitOperations.RotateLeft(B, 30);
            B = A;
            A = tmp;

            round++;
        }

        while(round < 60)
        {
            tmp = BitOperations.RotateLeft(A, 5) + G(B, C, D) + E + 0x8f1bbcdcu + buffer[round];
            E = D;
            D = C;
            C = BitOperations.RotateLeft(B, 30);
            B = A;
            A = tmp;

            round++;
        }

        while(round < 80)
        {
            tmp = BitOperations.RotateLeft(A, 5) + H(B, C, D) + E + 0xca62c1d6u + buffer[round];
            E = D;
            D = C;
            C = BitOperations.RotateLeft(B, 30);
            B = A;
            A = tmp;

            round++;
        }

        ArrayPool<uint>.Shared.Return(buffer, false);

        state->H[0] += A;
        state->H[1] += B;
        state->H[2] += C;
        state->H[3] += D;
        state->H[4] += E;
    }

    private unsafe void ComputeHashUnsafe(byte* data, long length, SHA1State* state)
    {
        for (int i = 0; i < (length >> 6); i++)
        {
            ComputeInternal(state, data + (i << 6));
        }

        int data_len_mod_0x3F = (int)((length + 1L) & 0x3FL);
        byte[] padding = new byte[128];

        int k = 64;
        if (data_len_mod_0x3F > 56) k = 0;

        for (int i = 0; i < data_len_mod_0x3F - 1; i++)
        {
            padding[i + k] = data[length - data_len_mod_0x3F + 1 + i];
        }

        padding[k + data_len_mod_0x3F - 1] = 0x80;

        long wholeSize = (length) << 3;
        byte* wholeSizePtr = (byte*)&wholeSize;

        padding[127] = wholeSizePtr[0];
        padding[126] = wholeSizePtr[1];
        padding[125] = wholeSizePtr[2];
        padding[124] = wholeSizePtr[3];
        padding[123] = wholeSizePtr[4];
        padding[122] = wholeSizePtr[5];
        padding[121] = wholeSizePtr[6];
        padding[120] = wholeSizePtr[7];

        fixed (byte* ptr = &padding[0])
        {
            if (data_len_mod_0x3F > 56) ComputeInternal(state, ptr);

            ComputeInternal(state, ptr + 64);
        }
    }
}