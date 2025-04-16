using Hyperledger.Ursa.BbsSignatures;
using Multiformats.Base;
using System.Text;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Test_DID
{
    public class BbsSignatureFactory : ISignatureFactory
    {
        private readonly IBbsSignatureService service;

        public BbsSignatureFactory()
        {
            service = new BbsSignatureService();
        }

        public string MethodName => "bbs";
        public string ProofType => "BbsBlsSignature2020";
        public string Context => "https://w3id.org/security/bbs/v1";

        public byte[] Sign(byte[] privateKey, byte[] data)
        {
            try
            {
                // Parse data as a VC to extract credentialSubject claims
                var vc = JObject.Parse(Encoding.UTF8.GetString(data));
                var credentialSubject = vc["credentialSubject"] as JArray;
                if (credentialSubject == null)
                {
                    throw new ArgumentException("credentialSubject must be an array for BBS+ signing.");
                }

                // Handle single-object credentialSubject (temporary fallback)
                var messages = new List<string>();
                if (credentialSubject.Count == 1 && credentialSubject[0] is JObject subjectObj)
                {
                    // Extract individual fields as separate messages
                    if (subjectObj["id"] is JArray idArray && idArray.Count > 0)
                        messages.Add(new JObject { ["id"] = idArray[0] }.ToString(Newtonsoft.Json.Formatting.None));
                    if (subjectObj["name"] is JArray nameArray && nameArray.Count > 0)
                        messages.Add(new JObject { ["name"] = nameArray[0] }.ToString(Newtonsoft.Json.Formatting.None));
                    if (subjectObj["driver_type"] is JArray driverTypeArray && driverTypeArray.Count > 0)
                        messages.Add(new JObject { ["driver_type"] = driverTypeArray[0] }.ToString(Newtonsoft.Json.Formatting.None));
                }
                else
                {
                    // Preferred structure: each array element is a claim
                    messages.AddRange(credentialSubject.Select(claim => claim.ToString(Newtonsoft.Json.Formatting.None)));
                }

                if (messages.Count == 0)
                {
                    throw new ArgumentException("No valid claims found in credentialSubject.");
                }

                var blsKeyPair = new BlsKeyPair(privateKey);
                var signRequest = new SignRequest(blsKeyPair, messages.ToArray());
                return service.Sign(signRequest);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error signing with BBS+: {ex.Message}", ex);
            }
        }

        public bool Verify(string publicKeyMultibase, byte[] data, byte[] signature)
        {
            try
            {
                // Parse data as a VC to extract credentialSubject claims
                var vc = JObject.Parse(Encoding.UTF8.GetString(data));
                var credentialSubject = vc["credentialSubject"] as JArray;
                if (credentialSubject == null)
                {
                    throw new ArgumentException("credentialSubject must be an array for BBS+ verification.");
                }

                // Handle single-object credentialSubject (temporary fallback)
                var messages = new List<string>();
                if (credentialSubject.Count == 1 && credentialSubject[0] is JObject subjectObj)
                {
                    if (subjectObj["id"] is JArray idArray && idArray.Count > 0)
                        messages.Add(new JObject { ["id"] = idArray[0] }.ToString(Newtonsoft.Json.Formatting.None));
                    if (subjectObj["name"] is JArray nameArray && nameArray.Count > 0)
                        messages.Add(new JObject { ["name"] = nameArray[0] }.ToString(Newtonsoft.Json.Formatting.None));
                    if (subjectObj["driver_type"] is JArray driverTypeArray && driverTypeArray.Count > 0)
                        messages.Add(new JObject { ["driver_type"] = driverTypeArray[0] }.ToString(Newtonsoft.Json.Formatting.None));
                }
                else
                {
                    messages.AddRange(credentialSubject.Select(claim => claim.ToString(Newtonsoft.Json.Formatting.None)));
                }

                if (messages.Count == 0)
                {
                    throw new ArgumentException("No valid claims found in credentialSubject.");
                }

                // Decode public key
                byte[] publicKeyBytes = Multibase.Base58.Decode(publicKeyMultibase.Substring(1));
                // BLS12-381 G2 public key should be 48 bytes (excluding 2-byte prefix)
                if (publicKeyBytes.Length < 50) // 48 + 2-byte prefix
                {
                    throw new ArgumentException("Public key is too short for BLS12-381 G2.");
                }
                byte[] rawPublicKey = new byte[publicKeyBytes.Length - 2];
                Array.Copy(publicKeyBytes, 2, rawPublicKey, 0, rawPublicKey.Length);
                if (rawPublicKey.Length != 48)
                {
                    throw new ArgumentException($"Expected 48-byte BLS12-381 G2 public key, got {rawPublicKey.Length} bytes.");
                }
                var blsKeyPair = new BlsKeyPair(rawPublicKey);

                var verifyRequest = new VerifyRequest(blsKeyPair, signature, messages.ToArray());
                return service.Verify(verifyRequest);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error verifying BBS+ signature: {ex.Message}", ex);
            }
        }

        public byte[] DeriveProof(byte[] originalProof, List<int> disclosedIndices, List<JObject> credentialSubject, string publicKeyMultibase, out string nonce)
        {
            try
            {
                // Handle single-object credentialSubject
                var messages = new List<ProofMessage>();
                int messageCount;
                if (credentialSubject.Count == 1 && credentialSubject[0] is JObject subjectObj)
                {
                    var claims = new List<JObject>();
                    if (subjectObj["id"] is JArray idArray && idArray.Count > 0)
                        claims.Add(new JObject { ["id"] = idArray[0] });
                    if (subjectObj["name"] is JArray nameArray && nameArray.Count > 0)
                        claims.Add(new JObject { ["name"] = nameArray[0] });
                    if (subjectObj["driver_type"] is JArray driverTypeArray && driverTypeArray.Count > 0)
                        claims.Add(new JObject { ["driver_type"] = driverTypeArray[0] });
                    messageCount = claims.Count;
                    messages.AddRange(claims.Select((claim, index) => new ProofMessage
                    {
                        Message = claim.ToString(Newtonsoft.Json.Formatting.None),
                        ProofType = disclosedIndices.Contains(index) ? ProofMessageType.Revealed : ProofMessageType.HiddenProofSpecificBlinding
                    }));
                }
                else
                {
                    messageCount = credentialSubject.Count;
                    messages.AddRange(credentialSubject.Select((claim, index) => new ProofMessage
                    {
                        Message = claim.ToString(Newtonsoft.Json.Formatting.None),
                        ProofType = disclosedIndices.Contains(index) ? ProofMessageType.Revealed : ProofMessageType.HiddenProofSpecificBlinding
                    }));
                }

                if (disclosedIndices.Any(i => i < 0 || i >= messageCount))
                {
                    throw new ArgumentException("Invalid disclosed indices.");
                }

                // Decode public key
                byte[] publicKeyBytes = Multibase.Base58.Decode(publicKeyMultibase.Substring(1));
                // Expect 98 bytes (2-byte prefix + 96-byte key)
                if (publicKeyBytes.Length != 98)
                {
                    throw new ArgumentException($"Expected 98-byte encoded BLS12-381 G2 public key (with prefix), got {publicKeyBytes.Length} bytes.");
                }
                // Extract the 96-byte key (skip 2-byte prefix: 0xEA, 0x01)
                byte[] rawPublicKey = new byte[96];
                Array.Copy(publicKeyBytes, 2, rawPublicKey, 0, 96);

                // Create BbsKeyPair
                var bbsKeyPair = new BbsKeyPair(rawPublicKey, (uint)messageCount);

                nonce = Convert.ToBase64String(GenerateNonce());

                var proofRequest = new CreateProofRequest(
                    publicKey: bbsKeyPair,
                    messages: messages.ToArray(),
                    signature: originalProof,
                    blindingFactor: null,
                    nonce: nonce
                );

                return service.CreateProof(proofRequest);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error creating BBS+ proof: {ex.Message}", ex);
            }
        }

        public bool VerifyDerivedProof(string publicKeyMultibase, byte[] vcBytes, byte[] derivedProof, List<JObject> disclosedClaims, string nonce)
        {
            try
            {
                byte[] publicKeyBytes = Multibase.Base58.Decode(publicKeyMultibase.Substring(1));
                if (publicKeyBytes.Length != 98)
                {
                    throw new ArgumentException($"Expected 98-byte encoded BLS12-381 G2 public key (with prefix), got {publicKeyBytes.Length} bytes.");
                }
                byte[] rawPublicKey = new byte[96];
                Array.Copy(publicKeyBytes, 2, rawPublicKey, 0, 96);

                var bbsKeyPair = new BbsKeyPair(rawPublicKey, (uint)disclosedClaims.Count);

                var disclosedMessages = disclosedClaims
                    .Select((claim, index) => new IndexedMessage
                    {
                        Message = claim.ToString(Newtonsoft.Json.Formatting.None),
                        Index = (uint)index
                    })
                    .ToArray();

                var verifyProofRequest = new VerifyProofRequest
                (
                    publicKey: bbsKeyPair,
                    proof: derivedProof,
                    messages: disclosedMessages,
                    nonce: nonce
                );

                var result = service.VerifyProof(verifyProofRequest);
                return result == SignatureProofStatus.Success;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error verifying BBS+ derived proof: {ex.Message}", ex);
            }
        }

        private byte[] GenerateNonce()
        {
            var nonce = new byte[32];
            RandomNumberGenerator.Fill(nonce);
            return nonce;
        }
    }
}