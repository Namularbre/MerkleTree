using System.Security.Cryptography;
using System.Text;

namespace MerkleTree;

/// <summary>
/// Able to compute hash with algorithm based on RFC 9162
/// </summary>
public static class HashService
{
    public static byte[] LeafHash(string rawData)
    {
        byte[] data = Encoding.UTF8.GetBytes(rawData);
        byte[] buf = new byte[1 + data.Length];
        buf[0] = 0x00;
        data.CopyTo(buf, 1);
        return SHA256.HashData(buf);
    }

    public static byte[] NodeHash(byte[] left, byte[] right)
    {
        byte[] buf = new byte[1 + left.Length + right.Length];
        buf[0] = 0x01;
        left.CopyTo(buf, 1);
        right.CopyTo(buf, 1 + left.Length);
        return SHA256.HashData(buf);
    }

    /// <summary>
    /// Compute the hashes of a subtree
    /// </summary>
    /// <param name="logs">All the logs</param>
    /// <param name="start">The start index</param>
    /// <param name="numberOfLeavesInRange">Number of leaves in the range (not the size of the list).</param>
    /// <returns></returns>
    public static byte[] SubtreeHash(IReadOnlyList<string> logs, int start, int numberOfLeavesInRange)
    {
        if (start + numberOfLeavesInRange > logs.Count)
            throw new ArgumentOutOfRangeException(nameof(numberOfLeavesInRange), "Range is bigger than the end of the list");
        
        if (numberOfLeavesInRange == 0) return SHA256.HashData([]);
        if (numberOfLeavesInRange == 1) return LeafHash(logs[start]);

        var k = 1;

        while (k * 2 < numberOfLeavesInRange) k *= 2;
        return NodeHash(SubtreeHash(logs, start, k), SubtreeHash(logs, start + k, numberOfLeavesInRange - k));
    }
}
