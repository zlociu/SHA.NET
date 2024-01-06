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
    private readonly byte[] buffer;
    private int bufferLen;

    public Sha1()
    {
        this.state = new();
        this.buffer = new byte[64];
        this.bufferLen = 0;
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe byte[] GetHashByteArray(uint* ptr, int len)
    {
        var result = new byte[len];

        byte* bytePtr = (byte*)ptr;
        for(int i = 0; i < len; i++) result[i] = bytePtr[i ^ 3];
        return result;
    }

    public unsafe byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        SHA1State state = new();
        SHA1State* statePtr = &state;
        
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
         
        return GetHashByteArray(statePtr->H, 20);
    }

    public unsafe byte[] ComputeHash(byte[] data)
    {
        SHA1State state = new();
        SHA1State* statePtr = &state;
        
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

        return GetHashByteArray(statePtr->H, 20);
    }

    public unsafe byte[] ComputeHash(Stream data)
    {
        SHA1State state = new();
        SHA1State* statePtr = &state;

        if (data is null || data.Length == 0)
        {
            this.ComputeHashUnsafe(null, 0, statePtr);
        }
        else
        {
            this.ComputeHashStreamUnsafe(data, statePtr);
        }

        return GetHashByteArray(statePtr->H, 20);
    }

    public unsafe void Clear()
    {
        this.state = new();
        this.bufferLen = 0;
    }

    public unsafe string Hash => string.Format("{0:x8}{1:x8}{2:x8}{3:x8}{4:x8}", state.H[0], state.H[1], state.H[2], state.H[3], state.H[4]);

    public int HashSizeBits => 160;
    public int HashSizeBytes => 20;
    public string Name => "SHA-1";

    public unsafe void HashData(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return;

        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            fixed (SHA1State* state = &this.state)
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
            fixed (SHA1State* state = &this.state)
            {
                this.HashDataUnsafe(ptr, size, state);
            }
        }
    }

    public unsafe void HashFinal()
    {
        fixed (byte* ptr = &this.buffer[0])
        {
            fixed (SHA1State* state = &this.state)
            {
                this.ComputeFinalInternal(state, ptr, this.bufferLen);
            }
        }
    }

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

    private unsafe void ComputeFinalInternal(SHA1State* state, byte* data, long length)
    {
        int data_len_mod_0x3F = (int)((length + 1L) & 0x3FL);
        byte[] padding = new byte[128];
        
        int k = 64;
        if (data_len_mod_0x3F > 56) k = 0;

        fixed (byte* paddingPtr = &padding[0])
        {
            Buffer.MemoryCopy(
                data + length - data_len_mod_0x3F + 1,
                paddingPtr + k,
                data_len_mod_0x3F - 1,
                data_len_mod_0x3F - 1);
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

    private unsafe void ComputeHashUnsafe(byte* data, long length, SHA1State* state)
    {
        for (int i = 0; i < (length >> 6); i++)
        {
            this.ComputeInternal(state, data + (i << 6));
        }

        int lenFullChunks = (int)(length & ~0x3FL);
        this.ComputeFinalInternal(state, data + lenFullChunks, length - lenFullChunks);
    }

    private unsafe void ComputeHashStreamUnsafe(Stream stream, SHA1State* state)
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

    private unsafe void HashDataUnsafe(byte* data, int length, SHA1State* state)
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