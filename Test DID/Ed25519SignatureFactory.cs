using Multiformats.Base;
using Newtonsoft.Json.Linq;
using NSec.Cryptography;

namespace Test_DID;

public class Ed25519SignatureFactory : ISignatureFactory
{
    private readonly SignatureAlgorithm algorithm = SignatureAlgorithm.Ed25519;

    public string MethodName => "ed25519";
    public string ProofType => "Ed25519Signature2020";
    public string Context => "https://w3id.org/security/v2";

    public byte[] Sign(byte[] privateKey, byte[] data)
    {
        var key = Key.Import(algorithm, privateKey, KeyBlobFormat.RawPrivateKey);
        return algorithm.Sign(key, data);
    }

    public bool Verify(string publicKeyMultibase, byte[] data, byte[] signature)
    {
        byte[] publicKeyBytes = Multibase.Base58.Decode(publicKeyMultibase.Substring(1));
        byte[] rawPublicKey = new byte[publicKeyBytes.Length - 2];
        Array.Copy(publicKeyBytes, 2, rawPublicKey, 0, rawPublicKey.Length);
        var publicKey = PublicKey.Import(algorithm, rawPublicKey, KeyBlobFormat.RawPublicKey);
        return algorithm.Verify(publicKey, data, signature);
    }

    public byte[] DeriveProof(byte[] originalProof, List<int> disclosedIndices, List<JObject> credentialSubject, string publicKeyMultibase, out string nonce)
    {
        nonce = null;
        throw new NotImplementedException();
    }

    public bool VerifyDerivedProof(string publicKeyMultibase, byte[] vcBytes, byte[] derivedProof, List<JObject> disclosedClaims, string nonce)
    {
        throw new NotImplementedException();
    }
}
