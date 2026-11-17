using System.Buffers.Binary;
using System.Security.Cryptography;
using NSec.Cryptography;

namespace MerkleTree;

/// <summary>
/// Signs and verifies Signed Tree Heads (STH) with an Ed25519 key pair.
/// </summary>
/// <remarks>
/// <para>The signature covers a canonical, fixed-size encoding of the whole tree head
/// (see <see cref="BuildPayload"/>), so neither the tree size, the timestamp nor the root hash
/// can be changed without invalidating the signature.</para>
/// <para>The private key is held by NSec in protected memory: dispose the signer when it is no longer needed.</para>
/// </remarks>
public sealed class TreeHeadSigner : IDisposable
{
    /// <summary>Size in bytes of an Ed25519 private key seed.</summary>
    public const int PrivateKeySize = 32;

    /// <summary>Size in bytes of a root hash (SHA-256).</summary>
    public const int RootHashSize = 32;

    /// <summary>Version byte of the signed payload format, so the encoding can evolve without ambiguity.</summary>
    private const byte PayloadVersion = 0x01;

    /// <summary>Size in bytes of the signed payload: version (1) + tree size (8) + timestamp (8) + root hash (32).</summary>
    private const int PayloadSize = 1 + sizeof(long) + sizeof(long) + RootHashSize;

    private static readonly SignatureAlgorithm Algorithm = SignatureAlgorithm.Ed25519;

    /// <summary>The Ed25519 private key, imported once and kept in NSec's protected memory.</summary>
    private readonly Key _privateKey;

    /// <summary>The clock used to timestamp tree heads.</summary>
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Gets the Ed25519 public key that clients use to verify the signatures.
    /// </summary>
    public PublicKey PublicKey { get; }

    /// <summary>
    /// Creates a signer from an existing Ed25519 private key.
    /// </summary>
    /// <param name="privateKey">
    /// The 32-byte Ed25519 private key seed. The array is wiped (filled with zeros) once the key has been imported,
    /// so the caller must not reuse it.
    /// </param>
    /// <param name="timeProvider">The clock used to timestamp tree heads. Defaults to <see cref="TimeProvider.System"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="privateKey"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="privateKey"/> is not 32 bytes long.</exception>
    public TreeHeadSigner(byte[] privateKey, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        if (privateKey.Length != PrivateKeySize)
            throw new ArgumentException($"An Ed25519 private key must be {PrivateKeySize} bytes long.", nameof(privateKey));

        try
        {
            _privateKey = Key.Import(Algorithm, privateKey, KeyBlobFormat.RawPrivateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }

        PublicKey = _privateKey.PublicKey;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Signs the given tree size and root hash, timestamped with the current time truncated to the millisecond.
    /// </summary>
    /// <param name="size">The size of the tree.</param>
    /// <param name="root">The 32-byte root hash of the tree of that size.</param>
    /// <returns>The Signed Tree Head.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="root"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="size"/> is negative.</exception>
    /// <exception cref="ArgumentException"><paramref name="root"/> is not 32 bytes long.</exception>
    /// <exception cref="ObjectDisposedException">The signer has been disposed.</exception>
    public SignedTreeHead Sign(long size, byte[] root)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentOutOfRangeException.ThrowIfNegative(size);
        if (root.Length != RootHashSize)
            throw new ArgumentException($"A root hash must be {RootHashSize} bytes long.", nameof(root));

        // Only milliseconds are signed: truncate first, so the STH holds exactly what was signed.
        long timestampMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeMilliseconds(timestampMs);

        // Copy the root so a later change to the caller's array cannot alter the STH.
        byte[] rootCopy = (byte[])root.Clone();
        byte[] signature = Algorithm.Sign(_privateKey, BuildPayload(size, rootCopy, timestamp));

        return new SignedTreeHead(size, rootCopy, timestamp, signature);
    }

    /// <summary>
    /// Checks that the signature of a Signed Tree Head is valid for its content and this signer's public key.
    /// </summary>
    /// <param name="head">The Signed Tree Head to verify.</param>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; <see langword="false"/> if it is not,
    /// or if <paramref name="head"/> is malformed.
    /// </returns>
    public bool Verify(SignedTreeHead? head) => Verify(PublicKey, head);

    /// <summary>
    /// Checks that the signature of a Signed Tree Head is valid for its content and the given public key.
    /// Only needs the public key, so it is what a client (who has no private key) uses.
    /// </summary>
    /// <param name="publicKey">The Ed25519 public key of the log.</param>
    /// <param name="head">The Signed Tree Head to verify.</param>
    /// <returns>
    /// <see langword="true"/> if the signature is valid; <see langword="false"/> if it is not,
    /// or if <paramref name="head"/> is malformed (<see langword="null"/>, negative size,
    /// root hash that is not 32 bytes long, missing signature).
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey"/> is <see langword="null"/>.</exception>
    public static bool Verify(PublicKey publicKey, SignedTreeHead? head)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        if (head?.RootHash is null || head.Signature is null) return false;
        if (head.TreeSize < 0 || head.RootHash.Length != RootHashSize) return false;
        if (head.Signature.Length != Algorithm.SignatureSize) return false;

        return Algorithm.Verify(publicKey, BuildPayload(head.TreeSize, head.RootHash, head.Timestamp), head.Signature);
    }

    /// <summary>
    /// Releases the private key.
    /// </summary>
    public void Dispose() => _privateKey.Dispose();

    /// <summary>
    /// Builds the canonical bytes that are signed:
    /// <c>version (1) || tree_size (8, big-endian) || timestamp in Unix ms (8, big-endian) || root_hash (32)</c>.
    /// </summary>
    /// <remarks>
    /// Every field has a fixed size, so two different tree heads can never produce the same payload.
    /// </remarks>
    /// <param name="treeSize">The size of the tree.</param>
    /// <param name="rootHash">The 32-byte root hash.</param>
    /// <param name="timestamp">The timestamp; only its Unix time in milliseconds is encoded.</param>
    /// <returns>The 49-byte payload.</returns>
    private static byte[] BuildPayload(long treeSize, byte[] rootHash, DateTimeOffset timestamp)
    {
        byte[] payload = new byte[PayloadSize];
        payload[0] = PayloadVersion;
        BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(1, sizeof(long)), treeSize);
        BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(1 + sizeof(long), sizeof(long)), timestamp.ToUnixTimeMilliseconds());
        rootHash.CopyTo(payload.AsSpan(1 + 2 * sizeof(long)));
        return payload;
    }
}
