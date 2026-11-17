namespace MerkleTree;

/// <summary>
/// A single entry of the append-only log. Each entry becomes one leaf of the Merkle tree.
/// </summary>
/// <param name="Index">The zero-based, sequential position of the entry in the log.</param>
/// <param name="ClientId">
/// An identifier chosen by the client (a UUID v7, see <see cref="Guid.CreateVersion7()"/>),
/// used to make appends idempotent: the same entry sent twice is only stored once.
/// </param>
/// <param name="ReceivedAt">The moment the log received the entry.</param>
/// <param name="Source">The system or component that produced the entry.</param>
/// <param name="Text">The content of the entry.</param>
public record LogEntry(long Index, Guid ClientId, DateTimeOffset ReceivedAt, string Source, string Text)
{
    /// <summary>
    /// Serializes the entry into a deterministic byte representation, which is the data hashed into the leaf.
    /// </summary>
    /// <remarks>
    /// Two equal entries must always produce the same bytes, whatever the machine, culture or time zone.
    /// </remarks>
    /// <returns>The canonical bytes of the entry.</returns>
    public byte[] ToCanonicalBytes()
    {
        throw new NotImplementedException();
    }
}
