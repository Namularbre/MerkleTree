using System.Security.Cryptography;

namespace MerkleTree.Tests;

public class MerkleHasherTests
{
    /// <summary>
    /// Leaf inputs of the official Certificate Transparency test vectors
    /// (LeafInputs() in https://github.com/transparency-dev/merkle/blob/main/testonly/constants.go).
    /// All are ASCII, so the UTF-8 encoding
    /// done by <see cref="MerkleHasher.LeafHash"/> yields exactly the reference bytes.
    /// </summary>
    private static readonly string[] CtLeaves =
    [
        "",
        "\0",
        "\u0010",
        " !",
        "01",
        "@ABC",
        "PQRSTUVW",
        "`abcdefghijklmno",
    ];

    /// <summary>
    /// Expected root hashes for the first n leaves of <see cref="CtLeaves"/>, n = 0..8
    /// (RootHashes() in the same file, indexed by tree size starting from the empty tree).
    /// </summary>
    public static TheoryData<int, string> CtRoots => new()
    {
        { 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { 1, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" },
        { 2, "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125" },
        { 3, "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77" },
        { 4, "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7" },
        { 5, "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4" },
        { 6, "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef" },
        { 7, "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c" },
        { 8, "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328" },
    };

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);

    // ---------- Official vectors ----------

    [Theory]
    [MemberData(nameof(CtRoots))]
    public void SubtreeHash_MatchesCertificateTransparencyRoots(int n, string expectedRoot)
    {
        byte[] root = MerkleHasher.SubtreeHash(CtLeaves, 0, n);

        Assert.Equal(expectedRoot, Hex(root));
    }

    [Fact]
    public void SubtreeHash_EmptyRange_IsSha256OfEmptyString()
    {
        byte[] root = MerkleHasher.SubtreeHash([], 0, 0);

        Assert.Equal(SHA256.HashData([]), root);
    }

    [Fact]
    public void SubtreeHash_SingleLeaf_IsLeafHash()
    {
        string[] logs = ["hello"];

        Assert.Equal(MerkleHasher.LeafHash("hello"), MerkleHasher.SubtreeHash(logs, 0, 1));
    }

    // ---------- LeafHash / NodeHash ----------

    [Fact]
    public void LeafHash_PrependsZeroByte()
    {
        byte[] expected = SHA256.HashData([0x00, (byte)'a', (byte)'b']);

        Assert.Equal(expected, MerkleHasher.LeafHash("ab"));
    }

    [Fact]
    public void LeafHash_EncodesInUtf8()
    {
        // "é" is 0xC3 0xA9 in UTF-8.
        byte[] expected = SHA256.HashData([0x00, 0xC3, 0xA9]);

        Assert.Equal(expected, MerkleHasher.LeafHash("é"));
    }

    [Fact]
    public void NodeHash_PrependsOneByteAndConcatenatesChildren()
    {
        byte[] left = [1, 2, 3];
        byte[] right = [4, 5];
        byte[] expected = SHA256.HashData([0x01, 1, 2, 3, 4, 5]);

        Assert.Equal(expected, MerkleHasher.NodeHash(left, right));
    }

    [Fact]
    public void NodeHash_IsNotCommutative()
    {
        byte[] a = MerkleHasher.LeafHash("a");
        byte[] b = MerkleHasher.LeafHash("b");

        Assert.NotEqual(MerkleHasher.NodeHash(a, b), MerkleHasher.NodeHash(b, a));
    }

    [Fact]
    public void LeafAndNodeHashes_AreDomainSeparated()
    {
        // The same bytes hashed as a leaf and as a node must not collide.
        byte[] a = MerkleHasher.LeafHash("a");
        byte[] b = MerkleHasher.LeafHash("b");
        byte[] node = MerkleHasher.NodeHash(a, b);

        Assert.NotEqual(node, SHA256.HashData([0x00, .. a, .. b]));
    }

    [Fact]
    public void Hashes_Are32BytesLong()
    {
        Assert.Equal(32, MerkleHasher.LeafHash("x").Length);
        Assert.Equal(32, MerkleHasher.NodeHash(new byte[32], new byte[32]).Length);
        Assert.Equal(32, MerkleHasher.SubtreeHash(CtLeaves, 0, 5).Length);
    }

    // ---------- Ranges ----------

    [Fact]
    public void SubtreeHash_TwoLeafRange_IsNodeOfTheTwoLeaves()
    {
        byte[] expected = MerkleHasher.NodeHash(MerkleHasher.LeafHash(CtLeaves[2]), MerkleHasher.LeafHash(CtLeaves[3]));

        Assert.Equal(expected, MerkleHasher.SubtreeHash(CtLeaves, 2, 2));
    }

    [Fact]
    public void SubtreeHash_SplitsOnLargestPowerOfTwoSmallerThanN()
    {
        // n = 5 -> k = 4: MTH(0..4) = NodeHash(MTH(0..3), MTH(4)).
        byte[] expected = MerkleHasher.NodeHash(
            MerkleHasher.SubtreeHash(CtLeaves, 0, 4),
            MerkleHasher.SubtreeHash(CtLeaves, 4, 1));

        Assert.Equal(expected, MerkleHasher.SubtreeHash(CtLeaves, 0, 5));
    }

    [Fact]
    public void SubtreeHash_PowerOfTwoSplitsInHalves()
    {
        // n = 8 -> k = 4 (strictly smaller than n, not 8).
        byte[] expected = MerkleHasher.NodeHash(
            MerkleHasher.SubtreeHash(CtLeaves, 0, 4),
            MerkleHasher.SubtreeHash(CtLeaves, 4, 4));

        Assert.Equal(expected, MerkleHasher.SubtreeHash(CtLeaves, 0, 8));
    }

    [Fact]
    public void SubtreeHash_AnyRange_EqualsRootOfTheSlice()
    {
        for (int start = 0; start <= CtLeaves.Length; start++)
        for (int n = 0; start + n <= CtLeaves.Length; n++)
        {
            string[] slice = CtLeaves[start..(start + n)];

            Assert.Equal(MerkleHasher.SubtreeHash(slice, 0, n), MerkleHasher.SubtreeHash(CtLeaves, start, n));
        }
    }

    [Fact]
    public void SubtreeHash_EmptyRangeAtEndOfList_IsAllowed()
    {
        Assert.Equal(SHA256.HashData([]), MerkleHasher.SubtreeHash(CtLeaves, CtLeaves.Length, 0));
    }

    [Fact]
    public void SubtreeHash_IgnoresLeavesOutsideTheRange()
    {
        string[] modified = (string[])CtLeaves.Clone();
        modified[0] = "changed";
        modified[7] = "changed";

        Assert.Equal(MerkleHasher.SubtreeHash(CtLeaves, 1, 6), MerkleHasher.SubtreeHash(modified, 1, 6));
    }

    [Fact]
    public void SubtreeHash_ChangingOneLeaf_ChangesTheRoot()
    {
        string[] modified = (string[])CtLeaves.Clone();
        modified[5] = "tampered";

        Assert.NotEqual(MerkleHasher.SubtreeHash(CtLeaves, 0, 8), MerkleHasher.SubtreeHash(modified, 0, 8));
    }

    [Fact]
    public void SubtreeHash_LeafOrderMatters()
    {
        string[] swapped = (string[])CtLeaves.Clone();
        (swapped[0], swapped[1]) = (swapped[1], swapped[0]);

        Assert.NotEqual(MerkleHasher.SubtreeHash(CtLeaves, 0, 8), MerkleHasher.SubtreeHash(swapped, 0, 8));
    }

    // ---------- Invalid arguments ----------

    [Fact]
    public void SubtreeHash_NegativeStart_Throws()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => MerkleHasher.SubtreeHash(CtLeaves, -1, 1));
        Assert.Equal("start", ex.ParamName);
    }

    [Fact]
    public void SubtreeHash_NegativeCount_Throws()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => MerkleHasher.SubtreeHash(CtLeaves, 0, -1));
        Assert.Equal("numberOfLeavesInRange", ex.ParamName);
    }

    [Theory]
    [InlineData(0, 9)]
    [InlineData(4, 5)]
    [InlineData(8, 1)]
    [InlineData(9, 0)]
    public void SubtreeHash_RangePastEndOfList_Throws(int start, int n)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => MerkleHasher.SubtreeHash(CtLeaves, start, n));
        Assert.Equal("numberOfLeavesInRange", ex.ParamName);
    }

    [Fact]
    public void SubtreeHash_HugeArguments_DoNotOverflow()
    {
        // start + n would overflow to a negative int if computed naively.
        Assert.Throws<ArgumentOutOfRangeException>(() => MerkleHasher.SubtreeHash(CtLeaves, 1, int.MaxValue));
    }

    [Fact]
    public void NullArguments_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => MerkleHasher.SubtreeHash(null!, 0, 0));
        Assert.Throws<ArgumentNullException>(() => MerkleHasher.LeafHash(null!));
        Assert.Throws<ArgumentNullException>(() => MerkleHasher.NodeHash(null!, []));
        Assert.Throws<ArgumentNullException>(() => MerkleHasher.NodeHash([], null!));
    }
}
