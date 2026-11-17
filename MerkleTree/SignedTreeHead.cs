namespace MerkleTree;

/// <summary>
/// A Signed Tree Head (STH): the log's signed commitment to its root hash at a given size.
/// </summary>
/// <param name="TreeSize">The number of entries in the tree when the head was signed.</param>
/// <param name="RootHash">The Merkle Tree Hash of the first <paramref name="TreeSize"/> entries.</param>
/// <param name="Timestamp">The moment the head was signed.</param>
/// <param name="Signature">The Ed25519 signature over the tree size, root hash and timestamp.</param>
public record SignedTreeHead(long TreeSize, byte[] RootHash, DateTimeOffset Timestamp, byte[] Signature);
