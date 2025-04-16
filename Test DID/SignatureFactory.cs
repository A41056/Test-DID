namespace Test_DID;

public static class SignatureFactory
{
    private static readonly Dictionary<string, ISignatureFactory> factories = new()
        {
            { "ed25519", new Ed25519SignatureFactory() },
            { "bbs", new BbsSignatureFactory() }
        };

    public static ISignatureFactory GetFactory(string method)
    {
        return factories.TryGetValue(method.ToLower(), out var factory) ? factory : throw new ArgumentException("Unsupported method.");
    }
}
