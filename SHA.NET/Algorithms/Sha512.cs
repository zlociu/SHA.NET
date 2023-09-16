namespace SHA.Algorithms;

using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public class Sha512 : IHashAlgorithm
{
    protected struct SHA512State
    {
        public unsafe fixed ulong H[8];

        public unsafe void Init512()
        {
            this.H[0] = 0x6a09e667f3bcc908UL;
            this.H[1] = 0xbb67ae8584caa73bUL;
            this.H[2] = 0x3c6ef372fe94f82bUL;
            this.H[3] = 0xa54ff53a5f1d36f1UL;
            this.H[4] = 0x510e527fade682d1UL;
            this.H[5] = 0x9b05688c2b3e6c1fUL;
            this.H[6] = 0x1f83d9abfb41bd6bUL;
            this.H[7] = 0x5be0cd19137e2179UL;
        }

        public unsafe void Init384()
        {
            this.H[0] = 0xcbbb9d5dc1059ed8UL;
            this.H[1] = 0x629a292a367cd507UL;
            this.H[2] = 0x9159015a3070dd17UL;
            this.H[3] = 0x152fecd8f70e5939UL;
            this.H[4] = 0x67332667ffc00b31UL;
            this.H[5] = 0x8eb44a8768581511UL;
            this.H[6] = 0xdb0c2e0d64f98fa7UL;
            this.H[7] = 0x47b5481dbefa4fa4UL;
        }
    }

    protected SHA512State state;

    public Sha512()
    {
        state = new();
        state.Init512();
    }

    protected virtual void InitState()
    {
        state.Init512();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected ulong Ch(ulong e, ulong f, ulong g)
    {
        return (e & f) ^ ((~e) & g);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected ulong Maj(ulong a, ulong b, ulong c)
    {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected ulong SmallSigma0(ulong a)
    {
        return
            BitOperations.RotateRight(a, 1) ^ 
            BitOperations.RotateRight(a, 8) ^ 
            (a >> 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected ulong SmallSigma1(ulong e)
    {
        return
            BitOperations.RotateRight(e, 19) ^ 
            BitOperations.RotateRight(e, 61) ^ 
            (e >> 6);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected ulong BigSigma0(ulong a)
    {
        return
            BitOperations.RotateRight(a, 28) ^ 
            BitOperations.RotateRight(a, 34) ^ 
            BitOperations.RotateRight(a, 39);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected ulong BigSigma1(ulong e)
    {
        return
            BitOperations.RotateRight(e, 14) ^ 
            BitOperations.RotateRight(e, 18) ^ 
            BitOperations.RotateRight(e, 41);
    }

    protected readonly static ulong[] kTable =
    {
        0x428A2F98D728AE22U, 0x7137449123EF65CDU, 0xB5C0FBCFEC4D3B2FU, 0xE9B5DBA58189DBBCU,
        0x3956C25BF348B538U, 0x59F111F1B605D019U, 0x923F82A4AF194F9BU, 0xAB1C5ED5DA6D8118U,
        0xD807AA98A3030242U, 0x12835B0145706FBEU, 0x243185BE4EE4B28CU, 0x550C7DC3D5FFB4E2U,
        0x72BE5D74F27B896FU, 0x80DEB1FE3B1696B1U, 0x9BDC06A725C71235U, 0xC19BF174CF692694U,
        0xE49B69C19EF14AD2U, 0xEFBE4786384F25E3U, 0x0FC19DC68B8CD5B5U, 0x240CA1CC77AC9C65U,
        0x2DE92C6F592B0275U, 0x4A7484AA6EA6E483U, 0x5CB0A9DCBD41FBD4U, 0x76F988DA831153B5U,
        0x983E5152EE66DFABU, 0xA831C66D2DB43210U, 0xB00327C898FB213FU, 0xBF597FC7BEEF0EE4U,
        0xC6E00BF33DA88FC2U, 0xD5A79147930AA725U, 0x06CA6351E003826FU, 0x142929670A0E6E70U,
        0x27B70A8546D22FFCU, 0x2E1B21385C26C926U, 0x4D2C6DFC5AC42AEDU, 0x53380D139D95B3DFU,
        0x650A73548BAF63DEU, 0x766A0ABB3C77B2A8U, 0x81C2C92E47EDAEE6U, 0x92722C851482353BU,
        0xA2BFE8A14CF10364U, 0xA81A664BBC423001U, 0xC24B8B70D0F89791U, 0xC76C51A30654BE30U,
        0xD192E819D6EF5218U, 0xD69906245565A910U, 0xF40E35855771202AU, 0x106AA07032BBD1B8U,
        0x19A4C116B8D2D0C8U, 0x1E376C085141AB53U, 0x2748774CDF8EEB99U, 0x34B0BCB5E19B48A8U,
        0x391C0CB3C5C95A63U, 0x4ED8AA4AE3418ACBU, 0x5B9CCA4F7763E373U, 0x682E6FF3D6B2B8A3U,
        0x748F82EE5DEFB2FCU, 0x78A5636F43172F60U, 0x84C87814A1F0AB72U, 0x8CC702081A6439ECU,
        0x90BEFFFA23631E28U, 0xA4506CEBDE82BDE9U, 0xBEF9A3F7B2C67915U, 0xC67178F2E372532BU,
        0xCA273ECEEA26619CU, 0xD186B8C721C0C207U, 0xEADA7DD6CDE0EB1EU, 0xF57D4F7FEE6ED178U,
        0x06F067AA72176FBAU, 0x0A637DC5A2C898A6U, 0x113F9804BEF90DAEU, 0x1B710B35131C471BU,
        0x28DB77F523047D84U, 0x32CAAB7B40C72493U, 0x3C9EBE0A15C9BEBCU, 0x431D67C49C100D4CU,
        0x4CC5D4BECB3E42B6U, 0x597F299CFC657E2AU, 0x5FCB6FAB3AD6FAECU, 0x6C44198C4A475817U
    };

    

    public unsafe void ComputeHash(ReadOnlySpan<byte> data)
    {
        this.InitState();

        fixed (SHA512State* statePtr = &this.state)
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
        this.InitState();

        fixed (SHA512State* statePtr = &this.state)
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

    public unsafe void ComputeHash(Stream data)
    {
        this.InitState();

        fixed (SHA512State* statePtr = &this.state)
        {
            if (data is null || data.Length == 0)
            {
                this.ComputeHashUnsafe(null, 0, statePtr);
                return;
            }

            this.ComputeHashStreamUnsafe(data, statePtr);
        }
    }

    public unsafe virtual string Hash => string.Format("0x{0:x16}{1:x16}{2:x16}{3:x16}{4:x16}{5:x16}{6:x16}{7:x16}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4], state.H[5], state.H[6], state.H[7]);
    
    public virtual int HashSizeBits => 512;
    public virtual int HashSizeBytes => 64;
    public virtual string Name => "SHA-512";

    protected unsafe void ComputeInternal(SHA512State* state, byte* data)
    {
        ulong A = state->H[0];
        ulong B = state->H[1];
        ulong C = state->H[2];
        ulong D = state->H[3];
        ulong E = state->H[4];
        ulong F = state->H[5];
        ulong G = state->H[6];
        ulong H = state->H[7];

        ulong[] buffer = ArrayPool<ulong>.Shared.Rent(80);
        byte* offsetPtr = data;
        int k = 0;

        while (k < 16)
        {
            buffer[k] =
                (((ulong)offsetPtr[(k * 8) + 0]) << 56) +
                (((ulong)offsetPtr[(k * 8) + 1]) << 48) +
                (((ulong)offsetPtr[(k * 8) + 2]) << 40) +
                (((ulong)offsetPtr[(k * 8) + 3]) << 32) +
                (((ulong)offsetPtr[(k * 8) + 4]) << 24) +
                (((ulong)offsetPtr[(k * 8) + 5]) << 16) +
                (((ulong)offsetPtr[(k * 8) + 6]) << 8) +
                (((ulong)offsetPtr[(k * 8) + 7]) << 0);

            k++;
        }

        while (k < 80)
        {
            buffer[k] = SmallSigma1(buffer[k - 2]) + buffer[k - 7] + SmallSigma0(buffer[k - 15]) + buffer[k - 16];
            k++;
        }

        ulong tmp1, tmp2 = 0;
        short round = 0;
        while (round < 80)
        {
            tmp1 = H + BigSigma1(E) + Ch(E, F, G) + kTable[round] + buffer[round];
            tmp2 = BigSigma0(A) + Maj(A, B, C);
            H = G;
            G = F;
            F = E;
            E = D + tmp1;
            D = C;
            C = B;
            B = A;
            A = tmp1 + tmp2;

            round++;
        }

        ArrayPool<ulong>.Shared.Return(buffer, false);

        state->H[0] += A;
        state->H[1] += B;
        state->H[2] += C;
        state->H[3] += D;
        state->H[4] += E;
        state->H[5] += F;
        state->H[6] += G;
        state->H[7] += H;
    }

    protected unsafe void ComputeHashUnsafe(byte* data, long length, SHA512State* state)
    {
        for (int i = 0; i < (length >> 7); i++)
        {
            this.ComputeInternal(state, data + (i << 7));
        }

        int data_len_mod_0x7F = (int)((length + 1L) & 0x7FL);
        byte[] padding = new byte[256];

        int k = 128;
        if (data_len_mod_0x7F > 112) k = 0;

        for (int i = 0; i < data_len_mod_0x7F - 1; i++)
        {
            padding[i + k] = data[length - data_len_mod_0x7F + 1 + i];
        }

        padding[k + data_len_mod_0x7F - 1] = 0x80;

        ulong wholeSizeSmall = (ulong)(length << 3);
        ulong wholeSize  = (ulong)((length >> 61) & 0x07);
        byte* wholeSizePtrSmall = (byte*)&wholeSizeSmall;
        byte* wholeSizePtr = (byte*)&wholeSize;

        padding[255] = wholeSizePtrSmall[0];
        padding[254] = wholeSizePtrSmall[1];
        padding[253] = wholeSizePtrSmall[2];
        padding[252] = wholeSizePtrSmall[3];
        padding[251] = wholeSizePtrSmall[4];
        padding[250] = wholeSizePtrSmall[5];
        padding[249] = wholeSizePtrSmall[6];
        padding[248] = wholeSizePtrSmall[7];

        padding[247] = wholeSizePtr[0];
        padding[246] = wholeSizePtr[1];
        padding[245] = wholeSizePtr[2];
        padding[244] = wholeSizePtr[3];
        padding[243] = wholeSizePtr[4];
        padding[242] = wholeSizePtr[5];
        padding[241] = wholeSizePtr[6];
        padding[240] = wholeSizePtr[7];

        fixed (byte* ptr = &padding[0])
        {
            if (data_len_mod_0x7F > 112) this.ComputeInternal(state, ptr);

            this.ComputeInternal(state, ptr + 128);
        }
    }

    private unsafe void ComputeHashStreamUnsafe(Stream stream, SHA512State* state)
    {
        var length = stream.Length;

        Span<byte> dataBuffer = stackalloc byte[128];
        
        int cnt = 0;

        fixed (byte* ptr = &MemoryMarshal.GetReference(dataBuffer))
        {
            while ((cnt = stream.Read(dataBuffer)) == 0x80)
            {
                ComputeInternal(state, ptr);
            }
        }

        int data_len_mod_0x7F = (int)((length + 1L) & 0x7FL);
        byte[] padding = new byte[256];

        int k = 128;
        if (data_len_mod_0x7F > 112) k = 0;

        for (int i = 0; i < data_len_mod_0x7F - 1; i++)
        {
            padding[i + k] = dataBuffer[cnt - data_len_mod_0x7F + 1 + i];
        }

        padding[k + data_len_mod_0x7F - 1] = 0x80;

        ulong wholeSizeSmall = (ulong)(length << 3);
        ulong wholeSize  = (ulong)((length >> 61) & 0x07);
        byte* wholeSizePtrSmall = (byte*)&wholeSizeSmall;
        byte* wholeSizePtr = (byte*)&wholeSize;

        padding[255] = wholeSizePtrSmall[0];
        padding[254] = wholeSizePtrSmall[1];
        padding[253] = wholeSizePtrSmall[2];
        padding[252] = wholeSizePtrSmall[3];
        padding[251] = wholeSizePtrSmall[4];
        padding[250] = wholeSizePtrSmall[5];
        padding[249] = wholeSizePtrSmall[6];
        padding[248] = wholeSizePtrSmall[7];

        padding[247] = wholeSizePtr[0];
        padding[246] = wholeSizePtr[1];
        padding[245] = wholeSizePtr[2];
        padding[244] = wholeSizePtr[3];
        padding[243] = wholeSizePtr[4];
        padding[242] = wholeSizePtr[5];
        padding[241] = wholeSizePtr[6];
        padding[240] = wholeSizePtr[7];

        fixed (byte* ptr = &padding[0])
        {
            if (data_len_mod_0x7F > 112) this.ComputeInternal(state, ptr);

            this.ComputeInternal(state, ptr + 128);
        }
    }
}