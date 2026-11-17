using System.Security.Cryptography;

namespace MerkleTree.Tests;

public class TreeHeadSignerTests
{
    /// <summary>A clock frozen at a given instant, so timestamps are predictable.</summary>
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static readonly byte[] Root = SHA256.HashData("root"u8);

    private static TreeHeadSigner NewSigner(TimeProvider? clock = null)
        => new(RandomNumberGenerator.GetBytes(TreeHeadSigner.PrivateKeySize), clock);

    // ---------- Valid signatures ----------

    [Fact]
    public void Sign_ThenVerify_Succeeds()
    {
        using var signer = NewSigner();

        SignedTreeHead sth = signer.Sign(8, Root);

        Assert.True(signer.Verify(sth));
    }

    [Fact]
    public void StaticVerify_WithOnlyThePublicKey_Succeeds()
    {
        using var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);

        Assert.True(TreeHeadSigner.Verify(signer.PublicKey, sth));
    }

    [Fact]
    public void Sign_EmptyTree_IsAllowed()
    {
        using var signer = NewSigner();

        SignedTreeHead sth = signer.Sign(0, SHA256.HashData([]));

        Assert.True(signer.Verify(sth));
    }

    [Fact]
    public void Sign_FillsTheTreeHeadFields()
    {
        var now = new DateTimeOffset(2026, 11, 17, 16, 0, 0, TimeSpan.Zero);
        using var signer = NewSigner(new FixedTimeProvider(now));

        SignedTreeHead sth = signer.Sign(42, Root);

        Assert.Equal(42, sth.TreeSize);
        Assert.Equal(Root, sth.RootHash);
        Assert.Equal(now, sth.Timestamp);
        Assert.Equal(64, sth.Signature.Length);
    }

    [Fact]
    public void Sign_TruncatesTimestampToTheMillisecond()
    {
        // 16:00:00.1234567 -> 16:00:00.123
        var now = new DateTimeOffset(2026, 11, 17, 16, 0, 0, TimeSpan.Zero).AddTicks(1_234_567);
        using var signer = NewSigner(new FixedTimeProvider(now));

        SignedTreeHead sth = signer.Sign(1, Root);

        Assert.Equal(now.ToUnixTimeMilliseconds(), sth.Timestamp.ToUnixTimeMilliseconds());
        Assert.Equal(0, sth.Timestamp.Ticks % TimeSpan.TicksPerMillisecond);
        Assert.True(signer.Verify(sth));
    }

    [Fact]
    public void Sign_CopiesTheRoot()
    {
        using var signer = NewSigner();
        byte[] root = (byte[])Root.Clone();

        SignedTreeHead sth = signer.Sign(8, root);
        root[0] ^= 0xFF;

        Assert.Equal(Root, sth.RootHash);
        Assert.True(signer.Verify(sth));
    }

    // ---------- Tampered tree heads ----------

    [Fact]
    public void Verify_FailsIfTreeSizeIsChanged()
    {
        using var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);

        Assert.False(signer.Verify(sth with { TreeSize = 9 }));
    }

    [Fact]
    public void Verify_FailsIfTimestampIsChanged()
    {
        using var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);

        Assert.False(signer.Verify(sth with { Timestamp = sth.Timestamp.AddMilliseconds(1) }));
    }

    [Fact]
    public void Verify_FailsIfRootHashIsChanged()
    {
        using var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);
        byte[] otherRoot = (byte[])sth.RootHash.Clone();
        otherRoot[^1] ^= 0x01;

        Assert.False(signer.Verify(sth with { RootHash = otherRoot }));
    }

    [Fact]
    public void Verify_FailsIfSignatureIsChanged()
    {
        using var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);
        byte[] signature = (byte[])sth.Signature.Clone();
        signature[0] ^= 0x01;

        Assert.False(signer.Verify(sth with { Signature = signature }));
    }

    [Fact]
    public void Verify_FailsWithAnotherKey()
    {
        using var signer = NewSigner();
        using var other = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);

        Assert.False(other.Verify(sth));
        Assert.False(TreeHeadSigner.Verify(other.PublicKey, sth));
    }

    // ---------- Malformed tree heads ----------

    [Fact]
    public void Verify_ReturnsFalseForMalformedHeads()
    {
        using var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);

        Assert.False(signer.Verify(null));
        Assert.False(signer.Verify(sth with { RootHash = new byte[31] }));
        Assert.False(signer.Verify(sth with { RootHash = new byte[33] }));
        Assert.False(signer.Verify(sth with { RootHash = null! }));
        Assert.False(signer.Verify(sth with { TreeSize = -1 }));
        Assert.False(signer.Verify(sth with { Signature = null! }));
        Assert.False(signer.Verify(sth with { Signature = new byte[63] }));
    }

    // ---------- Invalid arguments ----------

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(33)]
    public void Sign_RejectsRootOfWrongSize(int length)
    {
        using var signer = NewSigner();

        var ex = Assert.Throws<ArgumentException>(() => signer.Sign(8, new byte[length]));
        Assert.Equal("root", ex.ParamName);
    }

    [Fact]
    public void Sign_RejectsNullRoot()
    {
        using var signer = NewSigner();

        Assert.Throws<ArgumentNullException>(() => signer.Sign(8, null!));
    }

    [Fact]
    public void Sign_RejectsNegativeSize()
    {
        using var signer = NewSigner();

        Assert.Throws<ArgumentOutOfRangeException>(() => signer.Sign(-1, Root));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(31)]
    [InlineData(64)]
    public void Constructor_RejectsKeyOfWrongSize(int length)
    {
        Assert.Throws<ArgumentException>(() => new TreeHeadSigner(new byte[length]));
    }

    [Fact]
    public void Constructor_RejectsNullKey()
    {
        Assert.Throws<ArgumentNullException>(() => new TreeHeadSigner(null!));
    }

    [Fact]
    public void Static_Verify_RejectsNullPublicKey()
    {
        using var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);

        Assert.Throws<ArgumentNullException>(() => TreeHeadSigner.Verify(null!, sth));
    }

    // ---------- Key handling ----------

    [Fact]
    public void Constructor_WipesThePrivateKeyArray()
    {
        byte[] key = RandomNumberGenerator.GetBytes(TreeHeadSigner.PrivateKeySize);

        using var signer = new TreeHeadSigner(key);

        Assert.All(key, b => Assert.Equal(0, b));
    }

    [Fact]
    public void SameKey_GivesSamePublicKey()
    {
        byte[] key = RandomNumberGenerator.GetBytes(TreeHeadSigner.PrivateKeySize);

        using var a = new TreeHeadSigner((byte[])key.Clone());
        using var b = new TreeHeadSigner((byte[])key.Clone());

        Assert.True(a.PublicKey.Equals(b.PublicKey));
    }

    [Fact]
    public void Sign_AfterDispose_Throws()
    {
        var signer = NewSigner();
        signer.Dispose();

        Assert.Throws<ObjectDisposedException>(() => signer.Sign(8, Root));
    }

    [Fact]
    public void Verify_StillWorksAfterDispose()
    {
        var signer = NewSigner();
        SignedTreeHead sth = signer.Sign(8, Root);
        signer.Dispose();

        Assert.True(signer.Verify(sth));
    }
}
