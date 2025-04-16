using Newtonsoft.Json.Linq;

namespace Test_DID;

public interface ISignatureFactory
{
    string MethodName { get; }
    string ProofType { get; }
    string Context { get; }
    byte[] Sign(byte[] privateKey, byte[] data);
    bool Verify(string publicKeyMultibase, byte[] data, byte[] signature);
    byte[] DeriveProof(byte[] originalProof, List<int> disclosedIndices, List<JObject> credentialSubject, string publicKeyMultibase, out string nonce);
    bool VerifyDerivedProof(string publicKeyMultibase, byte[] vcBytes, byte[] derivedProof, List<JObject> disclosedClaims, string nonce);
}
