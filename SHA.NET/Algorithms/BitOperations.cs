namespace SHA.Algorithms;  

using System.Runtime.CompilerServices;

public static class BitOperations
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint RotateLeft(uint number, int bits)
    {
        return (number << bits) | (number >> (32 - bits));
    }
}