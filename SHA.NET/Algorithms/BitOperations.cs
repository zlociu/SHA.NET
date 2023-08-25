namespace SHA.Algorithms;  

using System.Runtime.CompilerServices;

public static class BitOperations
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateLeft(uint number, int bits)
    {
        return (number << bits) | (number >> (32 - bits));
    }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateLeft(ulong number, int bits)
    {
        return (number << bits) | (number >> (64 - bits));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateRight(uint number, int bits)
    {
        return (number >> bits) | (number << (32 - bits));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RotateRight(ulong number, int bits)
    {
        return (number >> bits) | (number << (64 - bits));
    }
}