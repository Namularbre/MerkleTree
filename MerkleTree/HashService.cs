using System.Security.Cryptography;
using System.Text;

namespace MerkleTree;

public static class HashService
{
    public static byte[] Hash(string data, HashAlgorithmName hashAlgorithmName)
    {
        using HashAlgorithm hashAlgorithm = hashAlgorithmName.Name switch
        {
            nameof(HashAlgorithmName.MD5) => MD5.Create(),
            nameof(HashAlgorithmName.SHA256) => SHA256.Create(),
            nameof(HashAlgorithmName.SHA384) => SHA384.Create(),
            nameof(HashAlgorithmName.SHA512) => SHA512.Create(),
            _ => throw new NotSupportedException("Not supported algorithm"),
        };
        
        return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    public static byte[] Hash(byte[] data, HashAlgorithmName hashAlgorithmName)
    {
        using HashAlgorithm hashAlgorithm = hashAlgorithmName.Name switch
        {
            nameof(HashAlgorithmName.MD5) => MD5.Create(),
            nameof(HashAlgorithmName.SHA256) => SHA256.Create(),
            nameof(HashAlgorithmName.SHA384) => SHA384.Create(),
            nameof(HashAlgorithmName.SHA512) => SHA512.Create(),
            _ => throw new NotSupportedException("Not supported algorithm"),
        };
        
        return hashAlgorithm.ComputeHash(data);
    }

    public static byte[] LeafHash(string rawData, HashAlgorithmName hashAlgorithmName)
    {
        byte[] data = Encoding.UTF8.GetBytes(rawData);
        byte[] buf = new byte[1 + data.Length];
        buf[0] = 0x00;
        data.CopyTo(buf, 1);
        return Hash(buf, hashAlgorithmName);
    }

    public static byte[] NodeHash(byte[] left, byte[] right, HashAlgorithmName hashAlgorithmName)
    {
        byte[] buf = new byte[1 + left.Length + right.Length];
        buf[0] = 0x01;
        left.CopyTo(buf, 1);
        right.CopyTo(buf, 1 + left.Length);
        return Hash(buf, hashAlgorithmName);
    }

    /// <summary>
    /// Compute the hashes of a subtree
    /// </summary>
    /// <param name="logs">All the logs</param>
    /// <param name="start">The start index</param>
    /// <param name="numberOfEntry">Number of entry in the list (IReadonlyList don't know its size, only capacity)</param>
    /// <param name="hashAlgorithmName">The HashAlgorithm we want to use</param>
    /// <returns></returns>
    public static byte[] MerkleTreeHash(IReadOnlyList<string> logs, int start, int numberOfEntry, HashAlgorithmName hashAlgorithmName)
    {
        if (numberOfEntry == 0) return Hash([], hashAlgorithmName);
        if (numberOfEntry == 1) return LeafHash(logs[0], hashAlgorithmName);

        int k = 1;

        while (k * 2 < numberOfEntry) k *= 2;
        return NodeHash(MerkleTreeHash(logs, start, k, hashAlgorithmName), MerkleTreeHash(logs, start + k, numberOfEntry - k, hashAlgorithmName), hashAlgorithmName);
    }
}
