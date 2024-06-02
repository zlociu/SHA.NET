namespace SHA.Algorithms;

using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public class Sha256 : IHashAlgorithm
{
    protected struct SHA256State
    {
        public unsafe fixed uint H[8];

        public unsafe void Init256()
        {
            this.H[0] = 0x6a09e667u;
            this.H[1] = 0xbb67ae85u;
            this.H[2] = 0x3c6ef372u;
            this.H[3] = 0xa54ff53au;
            this.H[4] = 0x510e527fu;
            this.H[5] = 0x9b05688cu;
            this.H[6] = 0x1f83d9abu;
            this.H[7] = 0x5be0cd19u;
        }

        public unsafe void Init224()
        {
            this.H[0] = 0xc1059ed8u;
            this.H[1] = 0x367cd507u;
            this.H[2] = 0x3070dd17u;
            this.H[3] = 0xf70e5939u;
            this.H[4] = 0xffc00b31u;
            this.H[5] = 0x68581511u;
            this.H[6] = 0x64f98fa7u;
            this.H[7] = 0xbefa4fa4u;
        }
    }
    protected SHA256State state;
    protected readonly byte[] buffer;
    protected int bufferLen;

    public Sha256()
    {
        this.state = new();
        this.state.Init256();
        this.buffer = new byte[64];
        this.bufferLen = 0;
    }

    public virtual void Clear()
    {
        this.state.Init256();
        this.bufferLen = 0;
    } 

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected uint Ch(uint e, uint f, uint g)
    {
        return (e & f) ^ ((~e) & g);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected uint Maj(uint a, uint b, uint c)
    {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected uint SmallSigma0(uint a)
    {
        return
            BitOperations.RotateRight(a, 7) ^ 
            BitOperations.RotateRight(a, 18) ^ 
            (a >> 3);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected uint SmallSigma1(uint e)
    {
        return
            BitOperations.RotateRight(e, 17) ^ 
            BitOperations.RotateRight(e, 19) ^ 
            (e >> 10);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected uint BigSigma0(uint a)
    {
        return
            BitOperations.RotateRight(a, 2) ^ 
            BitOperations.RotateRight(a, 13) ^ 
            BitOperations.RotateRight(a, 22);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected uint BigSigma1(uint e)
    {
        return
            BitOperations.RotateRight(e, 6) ^ 
            BitOperations.RotateRight(e, 11) ^ 
            BitOperations.RotateRight(e, 25);
    }

    protected readonly static uint[] kTable =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    protected virtual unsafe byte[] GetHashByteArray(uint* ptr)
    {
        var result = new byte[32];

        byte* bytePtr = (byte*)ptr;
        for(int i = 0; i < 32; i++) result[i] = bytePtr[i ^ 3];
        return result;
    }

    public unsafe byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        SHA256State state = new();
        state.Init256();
        SHA256State* statePtr = &state;

        if (data.Length == 0)
        {
            this.ComputeHashUnsafe(null, 0, statePtr);
        }
        else
        {
            fixed (byte* ptr = &MemoryMarshal.GetReference(data))
            {
                this.ComputeHashUnsafe(ptr, data.Length, statePtr);
            }
        }

        return this.GetHashByteArray(statePtr->H);
    }

    public unsafe byte[] ComputeHash(byte[] data)
    {
        SHA256State state = new();
        state.Init256();
        SHA256State* statePtr = &state;

        if (data is null || data.Length == 0)
        {
            this.ComputeHashUnsafe(null, 0, statePtr);
        }
        else
        {
            fixed (byte* ptr = &data[0])
            {
                this.ComputeHashUnsafe(ptr, data.Length, statePtr);
            }
        }

        return this.GetHashByteArray(statePtr->H);
    }

    public unsafe byte[] ComputeHash(Stream data)
    {
        SHA256State state = new();
        state.Init256();
        SHA256State* statePtr = &state;

        if (data is null || data.Length == 0)
        {
            this.ComputeHashUnsafe(null, 0, statePtr);
        }
        else
        {
            this.ComputeHashStreamUnsafe(data, statePtr);
        }

        return this.GetHashByteArray(statePtr->H);
    }

    public unsafe virtual string Hash => string.Format("{0:x8}{1:x8}{2:x8}{3:x8}{4:x8}{5:x8}{6:x8}{7:x8}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4], state.H[5], state.H[6], state.H[7]);
    
    public virtual int HashSizeBits => 256;
    public virtual int HashSizeBytes => 32;
    public virtual string Name => "SHA-256";

    public unsafe void HashData(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;

        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            fixed (SHA256State* state = &this.state)
            {
                this.HashDataUnsafe(ptr, data.Length, state);
            }
        }
    }

    public unsafe void HashData(byte[] data, int start, int size)
    {
        if (data is null) return;

        ArgumentOutOfRangeException.ThrowIfNegative(start);
        ArgumentOutOfRangeException.ThrowIfNegative(size);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(data.Length, start + size);

        fixed (byte* ptr = &data[start])
        {
            fixed (SHA256State* state = &this.state)
            {
                this.HashDataUnsafe(ptr, size, state);
            }
        }
    }

    public unsafe void HashFinal()
    {
        fixed (byte* ptr = &this.buffer[0])
        {
            fixed (SHA256State* state = &this.state)
            {
                this.ComputeFinalInternal(state, ptr, this.bufferLen);
            }
        }
    }

    protected unsafe void ComputeInternal(SHA256State* state, byte* data)
    {
        uint A = state->H[0];
        uint B = state->H[1];
        uint C = state->H[2];
        uint D = state->H[3];
        uint E = state->H[4];
        uint F = state->H[5];
        uint G = state->H[6];
        uint H = state->H[7];

        uint[] buffer = ArrayPool<uint>.Shared.Rent(64);
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

        while (k < 64)
        {
            buffer[k] = SmallSigma1(buffer[k - 2]) + buffer[k - 7] + SmallSigma0(buffer[k - 15]) + buffer[k - 16];
            k++;
        }

        uint tmp1, tmp2 = 0;
        short round = 0;
        while (round < 64)
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

        ArrayPool<uint>.Shared.Return(buffer, false);

        state->H[0] += A;
        state->H[1] += B;
        state->H[2] += C;
        state->H[3] += D;
        state->H[4] += E;
        state->H[5] += F;
        state->H[6] += G;
        state->H[7] += H;
    }

    private unsafe void ComputeHashUnsafe(byte* data, long length, SHA256State* state)
    {
        for (int i = 0; i < (length >> 6); i++)
        {
            this.ComputeInternal(state, data + (i << 6));
        }

        int lenFullChunks = (int)(length & ~0x3FL);
        this.ComputeFinalInternal(state, data + lenFullChunks, length - lenFullChunks);
    }

    private unsafe void ComputeFinalInternal(SHA256State* state, byte* data, long length)
    {
        int data_len_mod_0x3F = (int)((length + 1L) & 0x3FL);
        byte[] padding = new byte[128];

        int k = 64;
        if (data_len_mod_0x3F > 56) k = 0;

        int length_mod_0x3F = data_len_mod_0x3F - 1;

        for (int i = 0; i < length_mod_0x3F; i++)
        {
            padding[i + k] = data[length - length_mod_0x3F + i];
        }

        padding[length_mod_0x3F + k] = 0x80;

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

    private unsafe void ComputeHashStreamUnsafe(Stream stream, SHA256State* state)
    {
        Span<byte> dataBuffer = stackalloc byte[64];
        int cnt = 0;

        fixed (byte* ptr = &MemoryMarshal.GetReference(dataBuffer))
        {
            while ((cnt = stream.Read(dataBuffer)) == 0x40)
            {
                this.ComputeInternal(state, ptr);
            }

            this.ComputeFinalInternal(state, ptr, cnt);
        }
    }

    private unsafe void HashDataUnsafe(byte* data, int length, SHA256State* state)
    {
        fixed (byte* ptr = &this.buffer[0])
        {
            int len = 0x40 - this.bufferLen;
            if (length < len)
            {
                Buffer.MemoryCopy(data, ptr + this.bufferLen, length, length);
                this.bufferLen += length;
                return;
            }

            Buffer.MemoryCopy(data, ptr + this.bufferLen, len, len);
            
            ComputeInternal(state, ptr);
            this.bufferLen = 0;

            int lenFullChunks = (length - len) & ~0x3F;
            for (int i = 0; i < (lenFullChunks >> 6); i++)
            {
                ComputeInternal(state, data + len + (i << 6));
            }

            len = length - len - lenFullChunks;
            if (len > 0)
            {
                Buffer.MemoryCopy(data + length - len, ptr, len, len);

                this.bufferLen = len;
            }
        }
    }
}