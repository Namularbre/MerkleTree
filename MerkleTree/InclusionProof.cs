namespace MerkleTree;

/// <summary>
/// A proof that the leaf at <paramref name="LeafIndex"/> is included in the tree of size <paramref name="TreeSize"/>
/// (RFC 9162, section 2.1.3).
/// </summary>
/// <param name="LeafIndex">The zero-based index of the proven leaf.</param>
/// <param name="TreeSize">The size of the tree the proof is computed against.</param>
/// <param name="AuditPath">The sibling hashes needed to recompute the root, ordered from the leaf up to the root.</param>
public record InclusionProof(int LeafIndex, int TreeSize, List<byte[]> AuditPath);
