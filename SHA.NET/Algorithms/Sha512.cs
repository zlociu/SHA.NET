namespace SHA.Algorithms;

using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public class Sha512
{
    struct SHA512State
    {
        public unsafe fixed ulong H[8];

        public unsafe SHA512State()
        {
            this.H[0] = 0x6a09e667f3bcc908UL;
            this.H[1] = 0xa54ff53a5f1d36f1UL;
            this.H[2] = 0x1f83d9abfb41bd6bUL;
            this.H[3] = 0xbb67ae8584caa73bUL;
            this.H[4] = 0x3c6ef372fe94f82bUL;
            this.H[5] = 0x510e527fade682d1UL;
            this.H[6] = 0x9b05688c2b3e6c1fUL;
            this.H[7] = 0x5be0cd19137e2179UL;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong Ch(ulong e, ulong f, ulong g)
    {
        return (e & f) ^ ((~e) & g);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong Maj(ulong a, ulong b, ulong c)
    {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong SmallSigma0(ulong a)
    {
        return
            BitOperations.RotateRight(a, 1) ^ 
            BitOperations.RotateRight(a, 8) ^ 
            (a >> 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong SmallSigma1(ulong e)
    {
        return
            BitOperations.RotateRight(e, 19) ^ 
            BitOperations.RotateRight(e, 61) ^ 
            (e >> 6);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong BigSigma0(ulong a)
    {
        return
            BitOperations.RotateRight(a, 28) ^ 
            BitOperations.RotateRight(a, 34) ^ 
            BitOperations.RotateRight(a, 39);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private ulong BigSigma1(ulong e)
    {
        return
            BitOperations.RotateRight(e, 14) ^ 
            BitOperations.RotateRight(e, 18) ^ 
            BitOperations.RotateRight(e, 41);
    }

    private readonly static ulong[] kTable =
    {
        0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
        0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
        0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
        0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
        0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
        0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
        0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
        0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
        0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
        0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
        0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
    };

    private ulong[] result = Array.Empty<ulong>();

    public unsafe void ComputeHash(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            this.result = this.ComputeHashUnsafe(null, 0);
            return;
        }

        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            this.result = this.ComputeHashUnsafe(ptr, data.Length);
        }
    }

    public unsafe void ComputeHash(byte[] data)
    {
        if (data is null || data.Length == 0)
        {
            this.result = this.ComputeHashUnsafe(null, 0);
            return;
        }

        fixed (byte* ptr = &data[0])
        {
            this.result = this.ComputeHashUnsafe(ptr, data.Length);
        }
    }

    public string GetHash()
    {
        return string.Format("0x{0:x16}{1:x16}{2:x16}{3:x16}{4:x16}{5:x16}{6:x16}{7:x16}", result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7]);
    }


    private unsafe void ComputeInternal(SHA512State* state, byte* data)
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
                (((uint)offsetPtr[(k * 8) + 0]) << 56) +
                (((uint)offsetPtr[(k * 8) + 1]) << 48) +
                (((uint)offsetPtr[(k * 8) + 2]) << 40) +
                (((uint)offsetPtr[(k * 8) + 3]) << 32) +
                (((uint)offsetPtr[(k * 8) + 4]) << 24) +
                (((uint)offsetPtr[(k * 8) + 5]) << 16) +
                (((uint)offsetPtr[(k * 8) + 6]) << 8) +
                (((uint)offsetPtr[(k * 8) + 7]) << 0);

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

    private unsafe ulong[] ComputeHashUnsafe(byte* data, long length)
    {
        SHA512State state = new();

        for (int i = 0; i < (length >> 7); i++)
        {
            this.ComputeInternal(&state, data + (i << 7));
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

        UInt128 wholeSize = (UInt128)length;
        wholeSize <<= 3;
        byte[] wholeSizePtr = new byte[16];
        fixed (byte* numPtr = &wholeSizePtr[0])
        {
            *(UInt128*) numPtr = wholeSize;
        }

        padding[255] = wholeSizePtr[0];
        padding[254] = wholeSizePtr[1];
        padding[253] = wholeSizePtr[2];
        padding[252] = wholeSizePtr[3];
        padding[251] = wholeSizePtr[4];
        padding[250] = wholeSizePtr[5];
        padding[249] = wholeSizePtr[6];
        padding[248] = wholeSizePtr[7];

        padding[247] = wholeSizePtr[8];
        padding[246] = wholeSizePtr[9];
        padding[245] = wholeSizePtr[10];
        padding[244] = wholeSizePtr[11];
        padding[243] = wholeSizePtr[12];
        padding[242] = wholeSizePtr[13];
        padding[241] = wholeSizePtr[14];
        padding[240] = wholeSizePtr[15];

        fixed (byte* ptr = &padding[0])
        {
            if (data_len_mod_0x7F > 112) this.ComputeInternal(&state, ptr);

            this.ComputeInternal(&state, ptr + 128);
        }

        return new[] { state.H[0], state.H[1], state.H[2], state.H[3], state.H[4], state.H[5], state.H[6], state.H[7] };
    }
}