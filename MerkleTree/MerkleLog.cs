namespace MerkleTree;

/// <summary>
/// An append-only log backed by a Merkle tree (RFC 9162). Entries can only be added, never modified or removed,
/// and the log can prove both the inclusion of an entry and its own consistency over time.
/// </summary>
public class MerkleLog
{
    /// <summary>The entries of the log, in append order.</summary>
    private readonly List<LogEntry> _entries = [];

    /// <summary>The leaf hash of each entry, at the same index as in <see cref="_entries"/>.</summary>
    private readonly List<byte[]> _leafHashes = [];

    /// <summary>
    /// Cache of the subtree hashes already computed, keyed by <c>(start, n)</c>.
    /// Valid forever, since an append-only log never changes an existing range.
    /// </summary>
    private readonly Dictionary<(int Start, int N), byte[]> _subtreeCache = [];

    /// <summary>
    /// Gets the number of entries in the log.
    /// </summary>
    public int Count => throw new NotImplementedException();

    /// <summary>
    /// Appends a new entry at the end of the log.
    /// </summary>
    /// <param name="text">The content of the entry.</param>
    /// <returns>The index of the new entry.</returns>
    public long Append(string text)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Computes the root hash of the whole log.
    /// </summary>
    /// <returns>The 32-byte Merkle Tree Hash of all the entries.</returns>
    public byte[] Root()
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Computes the root hash of the log as it was when it contained <paramref name="n"/> entries.
    /// </summary>
    /// <param name="n">The size of the tree, between 0 and <see cref="Count"/>.</param>
    /// <returns>The 32-byte Merkle Tree Hash of the first <paramref name="n"/> entries.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="n"/> is negative or greater than <see cref="Count"/>.</exception>
    public byte[] Root(int n)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Builds the audit path proving that the entry at <paramref name="index"/> belongs to the tree of size <paramref name="n"/>.
    /// </summary>
    /// <param name="index">The zero-based index of the entry, lower than <paramref name="n"/>.</param>
    /// <param name="n">The size of the tree to prove against, between 1 and <see cref="Count"/>.</param>
    /// <returns>The inclusion proof.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="index"/> is not in <c>[0, n)</c>, or <paramref name="n"/> is greater than <see cref="Count"/>.
    /// </exception>
    public InclusionProof InclusionProof(int index, int n)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Builds the proof that the tree of size <paramref name="m"/> is a prefix of the tree of size <paramref name="n"/>.
    /// </summary>
    /// <param name="m">The size of the older tree, between 0 and <paramref name="n"/>.</param>
    /// <param name="n">The size of the newer tree, between <paramref name="m"/> and <see cref="Count"/>.</param>
    /// <returns>The consistency proof.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// The sizes do not satisfy <c>0 &lt;= m &lt;= n &lt;= Count</c>.
    /// </exception>
    public ConsistencyProof ConsistencyProof(int m, int n)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Computes the Merkle Tree Hash of the leaves <c>[start, start + n)</c> from the stored leaf hashes,
    /// using <see cref="_subtreeCache"/> to avoid recomputing known subtrees.
    /// </summary>
    /// <param name="start">The zero-based index of the first leaf of the range.</param>
    /// <param name="n">The number of leaves in the range.</param>
    /// <returns>The 32-byte Merkle Tree Hash of the range.</returns>
    private byte[] Mth(int start, int n)
    {
        throw new NotImplementedException();
    }
}
