using Newtonsoft.Json.Linq;

namespace Test_DID;

public interface ISignatureFactory
{
    string MethodName { get; }
    string ProofType { get; }
    string Context { get; }
    byte[] Sign(byte[] privateKey, byte[] data);
    bool Verify(string publicKeyMultibase, byte[] data, byte[] signature);
}
