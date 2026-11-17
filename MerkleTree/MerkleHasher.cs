using System.Security.Cryptography;
using System.Text;

namespace MerkleTree;

/// <summary>
/// Computes Merkle Tree Hashes (MTH) as specified in RFC 9162 (Certificate Transparency v2.0), section 2.1.1,
/// using SHA-256.
/// </summary>
/// <remarks>
/// Leaves and internal nodes use distinct one-byte prefixes (<c>0x00</c> and <c>0x01</c>) for domain separation,
/// which prevents second-preimage attacks where an internal node could be passed off as a leaf.
/// </remarks>
public static class MerkleHasher
{
    /// <summary>
    /// Computes the hash of a leaf: <c>SHA-256(0x00 || data)</c>.
    /// </summary>
    /// <param name="rawData">The leaf content. It is encoded in UTF-8 before hashing.</param>
    /// <returns>The 32-byte SHA-256 leaf hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rawData"/> is <see langword="null"/>.</exception>
    public static byte[] LeafHash(string rawData)
    {
        ArgumentNullException.ThrowIfNull(rawData);

        byte[] data = Encoding.UTF8.GetBytes(rawData);
        byte[] buf = new byte[1 + data.Length];
        buf[0] = 0x00;
        data.CopyTo(buf, 1);
        return SHA256.HashData(buf);
    }

    /// <summary>
    /// Computes the hash of an internal node: <c>SHA-256(0x01 || left || right)</c>.
    /// </summary>
    /// <param name="left">The hash of the left child.</param>
    /// <param name="right">The hash of the right child.</param>
    /// <returns>The 32-byte SHA-256 node hash.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="left"/> or <paramref name="right"/> is <see langword="null"/>.</exception>
    public static byte[] NodeHash(byte[] left, byte[] right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        byte[] buf = new byte[1 + left.Length + right.Length];
        buf[0] = 0x01;
        left.CopyTo(buf, 1);
        right.CopyTo(buf, 1 + left.Length);
        return SHA256.HashData(buf);
    }

    /// <summary>
    /// Computes the Merkle Tree Hash of the contiguous range of leaves
    /// <c>logs[start .. start + numberOfLeavesInRange - 1]</c>, as defined by RFC 9162.
    /// </summary>
    /// <remarks>
    /// <para>For a range of <c>n</c> leaves:</para>
    /// <list type="bullet">
    /// <item><description><c>n = 0</c>: the hash of the empty string, <c>SHA-256("")</c>.</description></item>
    /// <item><description><c>n = 1</c>: the leaf hash of the single entry (see <see cref="LeafHash"/>).</description></item>
    /// <item><description><c>n &gt; 1</c>: with <c>k</c> the largest power of two strictly smaller than <c>n</c>,
    /// <c>NodeHash(MTH(first k leaves), MTH(remaining n - k leaves))</c>.</description></item>
    /// </list>
    /// <para>Calling it with <c>start = 0</c> and <c>numberOfLeavesInRange = logs.Count</c> gives the root hash of the whole tree.</para>
    /// </remarks>
    /// <param name="logs">The ordered list of log entries (the leaves of the full tree). Only the requested range is read.</param>
    /// <param name="start">The zero-based index of the first leaf of the range.</param>
    /// <param name="numberOfLeavesInRange">The number of leaves in the range (not the size of <paramref name="logs"/>).</param>
    /// <returns>The 32-byte Merkle Tree Hash of the range.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="logs"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="start"/> or <paramref name="numberOfLeavesInRange"/> is negative,
    /// or the range goes past the end of <paramref name="logs"/>.
    /// </exception>
    public static byte[] SubtreeHash(IReadOnlyList<string> logs, int start, int numberOfLeavesInRange)
    {
        ArgumentNullException.ThrowIfNull(logs);
        ArgumentOutOfRangeException.ThrowIfNegative(start);
        ArgumentOutOfRangeException.ThrowIfNegative(numberOfLeavesInRange);

        // Written as a subtraction so that start + numberOfLeavesInRange cannot overflow.
        if (numberOfLeavesInRange > logs.Count - start)
            throw new ArgumentOutOfRangeException(nameof(numberOfLeavesInRange), "Range is bigger than the end of the list");

        if (numberOfLeavesInRange == 0) return SHA256.HashData([]);
        if (numberOfLeavesInRange == 1) return LeafHash(logs[start]);

        var k = 1;

        while (k * 2 < numberOfLeavesInRange) k *= 2;
        return NodeHash(SubtreeHash(logs, start, k), SubtreeHash(logs, start + k, numberOfLeavesInRange - k));
    }
}
