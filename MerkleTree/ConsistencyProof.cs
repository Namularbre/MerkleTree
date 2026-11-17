namespace MerkleTree;

/// <summary>
/// A proof that the tree of size <paramref name="OldSize"/> is a prefix of the tree of size <paramref name="NewSize"/>,
/// i.e. the log only appended entries in between (RFC 9162, section 2.1.4).
/// </summary>
/// <param name="OldSize">The size of the older tree.</param>
/// <param name="NewSize">The size of the newer tree.</param>
/// <param name="Path">The subtree hashes needed to recompute both roots.</param>
public record ConsistencyProof(int OldSize, int NewSize, List<byte[]> Path);
