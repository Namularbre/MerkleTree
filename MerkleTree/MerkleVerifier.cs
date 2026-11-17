namespace MerkleTree;

/// <summary>
/// Verifies Merkle proofs on the client side, without access to the log's content (RFC 9162, sections 2.1.3.2 and 2.1.4.2).
/// </summary>
public static class MerkleVerifier
{
    /// <summary>
    /// Checks that a leaf is included in the tree whose root is <paramref name="root"/>,
    /// by recomputing the root from the leaf hash and the audit path.
    /// </summary>
    /// <param name="leafHash">The leaf hash of the entry (see <see cref="MerkleHasher.LeafHash"/>).</param>
    /// <param name="proof">The inclusion proof returned by the log.</param>
    /// <param name="root">The trusted root hash of the tree of size <see cref="InclusionProof.TreeSize"/>.</param>
    /// <returns><see langword="true"/> if the recomputed root equals <paramref name="root"/>; otherwise <see langword="false"/>.</returns>
    public static bool VerifyInclusion(byte[] leafHash, InclusionProof proof, byte[] root)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Checks that the tree of root <paramref name="oldRoot"/> is a prefix of the tree of root <paramref name="newRoot"/>.
    /// </summary>
    /// <param name="oldRoot">The trusted root hash of the tree of size <see cref="ConsistencyProof.OldSize"/>.</param>
    /// <param name="newRoot">The root hash of the tree of size <see cref="ConsistencyProof.NewSize"/>.</param>
    /// <param name="proof">The consistency proof returned by the log.</param>
    /// <returns><see langword="true"/> if both roots can be recomputed from the proof; otherwise <see langword="false"/>.</returns>
    public static bool VerifyConsistency(byte[] oldRoot, byte[] newRoot, ConsistencyProof proof)
    {
        throw new NotImplementedException();
    }
}
