namespace MerkleTree;

/// <summary>
/// Signs and verifies Signed Tree Heads with an Ed25519 key pair.
/// </summary>
public class TreeHeadSigner
{
    /// <summary>The Ed25519 private key (32-byte seed) used to sign tree heads.</summary>
    private readonly byte[] _privateKey = null!;

    /// <summary>
    /// Gets the Ed25519 public key (32 bytes) that clients use to verify the signatures.
    /// </summary>
    public byte[] PublicKey => throw new NotImplementedException();

    /// <summary>
    /// Creates a signer from an existing Ed25519 private key.
    /// </summary>
    /// <param name="privateKey">The 32-byte Ed25519 private key seed.</param>
    /// <exception cref="ArgumentException"><paramref name="privateKey"/> is not 32 bytes long.</exception>
    public TreeHeadSigner(byte[] privateKey)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Signs the given tree size and root hash, timestamped with the current time.
    /// </summary>
    /// <param name="size">The size of the tree.</param>
    /// <param name="root">The root hash of the tree of that size.</param>
    /// <returns>The Signed Tree Head.</returns>
    public SignedTreeHead Sign(long size, byte[] root)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Checks that the signature of a Signed Tree Head is valid for its content and this signer's public key.
    /// </summary>
    /// <param name="head">The Signed Tree Head to verify.</param>
    /// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
    public bool Verify(SignedTreeHead head)
    {
        throw new NotImplementedException();
    }
}
