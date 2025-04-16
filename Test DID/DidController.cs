using Google.Protobuf;
using Microsoft.AspNetCore.Mvc;
using Multiformats.Base;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NSec.Cryptography;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Text;

namespace Test_DID
{
    [Route("api/did")]
    [ApiController]
    public class DidController : ControllerBase
    {
        private static readonly HttpClient client = new HttpClient();
        private static readonly string didFilePath = "didDocuments.json";

        private Dictionary<string, JObject> LoadDidDocuments()
        {
            if (System.IO.File.Exists(didFilePath))
            {
                string json = System.IO.File.ReadAllText(didFilePath);
                var deserialized = JsonConvert.DeserializeObject<Dictionary<string, JObject>>(json);
                return deserialized ?? new Dictionary<string, JObject>();
            }
            return new Dictionary<string, JObject>();
        }

        private void SaveDidDocuments(Dictionary<string, JObject> didDocuments)
        {
            string json = JsonConvert.SerializeObject(didDocuments, Formatting.Indented);
            System.IO.File.WriteAllText(didFilePath, json);
        }

        [HttpPost("generate-key")]
        public IActionResult GenerateKey([FromBody] GenerateKeyRequest request)
        {
            if (!new[] { "bbs", "ed25519" }.Contains(request.Method))
            {
                return BadRequest("Only 'bbs' and 'ed25519' methods are supported for key generation in this demo.");
            }

            byte[] privateKey;
            byte[] publicKey;

            if (request.Method == "bbs")
            {
                var bbsService = new BbsSignatureService();

                // Step 1: Generate keypair
                var keyPair = bbsService.GenerateBlsKey(BitConverter.GetBytes(DateTime.UtcNow.ToBinary()));
                privateKey = keyPair.SecretKey.ToByteArray();
                publicKey = keyPair.PublicKey.ToByteArray();

                // Multicodec-encode public key (0xea01 for BLS12-381 G2)
                byte[] multicodecBytes = new byte[] { 0xea, 0x01 };
                byte[] combinedBytes = new byte[multicodecBytes.Length + publicKey.Length];
                Array.Copy(multicodecBytes, 0, combinedBytes, 0, multicodecBytes.Length);
                Array.Copy(publicKey, 0, combinedBytes, multicodecBytes.Length, publicKey.Length);
                string publicKeyMultibase = Multibase.Base58.Encode(combinedBytes);

                // Step 2: Define messages
                var messages = new ProofMessage[]
                {
                    new ProofMessage { Message = "Alice", ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = "Proof of Age", ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = "Membership", ProofType = ProofMessageType.Revealed }
                };

                // Step 3: Sign the messages
                var signature = bbsService.Sign(new SignRequest(
                    keyPair: keyPair,
                    messages: messages.Select(x => x.Message).ToArray()
                ));

                // Step 4: Create BBS public key object with message count
                var bbsKeyPair = new BbsKeyPair(publicKey, (uint)messages.Length);

                var nonce = Convert.ToBase64String(GenerateNonce());

                // Step 5: Create a proof using the signature
                var proofRequest = new CreateProofRequest(
                    publicKey: bbsKeyPair,
                    messages: messages,
                    signature: signature,
                    blindingFactor: null,
                    nonce: nonce
                );
                var result = bbsService.CreateProof(proofRequest);

                // Step 6: Log the proof
                Trace.WriteLine("Generated proof: " + Convert.ToBase64String(result));

                return Ok(new
                {
                    PrivateKeyBase64 = Convert.ToBase64String(privateKey),
                    PublicKeyMultibase = $"z{publicKeyMultibase}",
                    ProofBase64 = Convert.ToBase64String(result)
                });
            }
            else // ed25519
            {
                var algorithm = SignatureAlgorithm.Ed25519;
                var creationParameters = new KeyCreationParameters
                {
                    ExportPolicy = KeyExportPolicies.AllowPlaintextExport
                };
                using var key = Key.Create(algorithm, creationParameters);
                privateKey = key.Export(KeyBlobFormat.RawPrivateKey);
                publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);

                byte[] multicodecBytes = new byte[] { 0xed, 0x01 };
                byte[] combinedBytes = new byte[multicodecBytes.Length + publicKey.Length];
                Array.Copy(multicodecBytes, 0, combinedBytes, 0, multicodecBytes.Length);
                Array.Copy(publicKey, 0, combinedBytes, multicodecBytes.Length, publicKey.Length);
                string publicKeyMultibase = Multibase.Base58.Encode(combinedBytes);

                return Ok(new
                {
                    PrivateKeyBase64 = Convert.ToBase64String(privateKey),
                    PublicKeyMultibase = $"z{publicKeyMultibase}"
                });
            }
        }

        [HttpPost("create")]
        public IActionResult CreateDid([FromBody] CreateDidRequest request)
        {
            string[] didParts = request.Did.Split(':');
            if (didParts.Length < 4 || didParts[0] != "did" || didParts[1] != "web")
            {
                return BadRequest("Invalid DID format. Expected: did:web:<domain>:<userId>");
            }
            string domain = didParts[2];
            string userId = didParts[3];
            string did = $"did:web:{domain}:{userId}";

            var contexts = new HashSet<string> { "https://www.w3.org/ns/did/v1" };
            var verificationMethods = new List<object>();
            var authentication = new List<string>();

            foreach (var method in request.Methods)
            {
                var factory = SignatureFactory.GetFactory(method);
                contexts.Add(factory.Context);

                verificationMethods.Add(new
                {
                    id = $"{did}#{method}",
                    type = factory.ProofType,
                    controller = did,
                    publicKeyMultibase = request.PublicKeyMultibases[method]
                });
                authentication.Add($"{did}#{method}");
            }

            var didDocument = new
            {
                context = contexts.ToArray(),
                id = did,
                verificationMethod = verificationMethods.ToArray(),
                authentication = authentication.ToArray()
            };

            var didDocuments = LoadDidDocuments();
            didDocuments[did] = JObject.FromObject(didDocument);
            SaveDidDocuments(didDocuments);

            return Ok(new { Did = did, DidDocument = didDocument });
        }

        [HttpGet("/{userId}/did.json")]
        public IActionResult GetDidDocument(string userId)
        {
            try
            {
                Console.WriteLine($"Received GET request for userId: {userId}");
                var didDocuments = LoadDidDocuments();
                Console.WriteLine($"Loaded didDocuments: {JsonConvert.SerializeObject(didDocuments)}");

                string didPrefix = $"did:web:";
                string matchingDid = null;
                foreach (var did in didDocuments.Keys)
                {
                    if (did.StartsWith(didPrefix) && did.EndsWith($":{userId}"))
                    {
                        matchingDid = did;
                        break;
                    }
                }

                Console.WriteLine($"Matching DID for userId {userId}: {matchingDid}");

                if (matchingDid != null && didDocuments.TryGetValue(matchingDid, out var didDocument))
                {
                    // Ép kiểu rõ ràng thành JObject và trả về
                    JObject document = didDocument as JObject ?? JObject.FromObject(didDocument);
                    Trace.WriteLine($"Returning DID Document: {document.ToString()}");
                    return Ok(document.ToString());
                }

                Console.WriteLine($"DID Document for userId {userId} not found.");
                return NotFound($"DID Document for userId {userId} not found.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in GetDidDocument: {ex.Message}");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        // Endpoint 2: Resolve DID
        [HttpPost("resolve")]
        public async Task<IActionResult> ResolveDid([FromBody] ResolveDidRequest request)
        {
            try
            {
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Add("Accept", "application/did+ld+json");
                string url = $"https://dev.uniresolver.io/1.0/identifiers/{request.Did}";
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();

                string didDocumentJson = await response.Content.ReadAsStringAsync();
                var formattedJson = JToken.Parse(didDocumentJson);
                return Ok(formattedJson.ToString());
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error resolving DID: {ex.Message}");
            }
        }

        // Endpoint 3: Ký VC
        [HttpPost("sign-vc")]
        public IActionResult SignVc([FromBody] SignVcRequest request)
        {
            try
            {
                var factory = SignatureFactory.GetFactory(request.Method);
                var contexts = new List<string> { "https://www.w3.org/2018/credentials/v1" };
                if (!contexts.Contains(factory.Context)) contexts.Add(factory.Context);

                var vc = new JObject
                {
                    ["@context"] = new JArray(contexts.ToArray()),
                    ["id"] = request.CredentialId,
                    ["type"] = new JArray("VerifiableCredential", request.CredentialType),
                    ["issuer"] = request.IssuerDid,
                    ["issuanceDate"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["credentialSubject"] = new JArray(request.CredentialSubject)
                };

                string vcJson = vc.ToString(Newtonsoft.Json.Formatting.None);
                byte[] vcBytes = Encoding.UTF8.GetBytes(vcJson);
                byte[] signature = factory.Sign(Convert.FromBase64String(request.PrivateKeyBase64), vcBytes);

                vc["proof"] = new JObject
                {
                    ["type"] = factory.ProofType,
                    ["created"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["verificationMethod"] = $"{request.IssuerDid}#{request.Method}",
                    ["proofValue"] = Convert.ToBase64String(signature)
                };

                return Ok(vc);
            }
            catch (Exception ex)
            {
                return BadRequest($"Error signing VC: {ex.Message}");
            }
        }

        // Endpoint 4: Xác minh VC
        [HttpPost("verify-vc")]
        public async Task<IActionResult> VerifyVc([FromBody] VerifyVcRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            try
            {
                var vcData = request.VerifiableCredential;
                string issuerDid = vcData.Issuer;
                string verificationMethod = vcData.Proof.VerificationMethod;
                string proofValue = vcData.Proof.ProofValue;
                string proofType = vcData.Proof.Type;

                // Reconstruct JObject for signature verification (since factory expects JObject)
                var vc = new JObject
                {
                    ["@context"] = vcData.Context,
                    ["id"] = vcData.Id,
                    ["type"] = vcData.Type,
                    ["issuer"] = vcData.Issuer,
                    ["issuanceDate"] = vcData.IssuanceDate,
                    ["credentialSubject"] = vcData.CredentialSubject,
                    ["proof"] = new JObject
                    {
                        ["type"] = vcData.Proof.Type,
                        ["created"] = vcData.Proof.Created,
                        ["verificationMethod"] = vcData.Proof.VerificationMethod,
                        ["proofValue"] = vcData.Proof.ProofValue
                    }
                };

                string method = verificationMethod.Split('#').Last().ToLower();
                ISignatureFactory factory;
                try
                {
                    factory = SignatureFactory.GetFactory(method);
                }
                catch (ArgumentException)
                {
                    return BadRequest($"Error: Unsupported signature method '{method}' for proof type '{proofType}'.");
                }

                if (factory.ProofType != proofType)
                {
                    return BadRequest($"Error: Proof type '{proofType}' does not match expected type '{factory.ProofType}' for method '{method}'.");
                }

                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Add("Accept", "application/did+ld+json");
                string url = $"https://dev.uniresolver.io/1.0/identifiers/{issuerDid}";
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();

                string didDocumentJson = await response.Content.ReadAsStringAsync();
                var didDocument = JObject.Parse(didDocumentJson);

                string publicKeyMultibase = null;
                JObject publicKeyJwk = null;
                foreach (var vm in didDocument["verificationMethod"] ?? new JArray())
                {
                    if (vm["id"]?.ToString() == verificationMethod)
                    {
                        publicKeyMultibase = vm["publicKeyMultibase"]?.ToString();
                        publicKeyJwk = vm["publicKeyJwk"] as JObject;
                        break;
                    }
                }

                if (string.IsNullOrEmpty(publicKeyMultibase) && publicKeyJwk == null)
                {
                    return BadRequest("Error: Could not find public key (multibase or JWK) in DID Document.");
                }

                vc.Remove("proof");
                string vcWithoutProof = vc.ToString(Formatting.None);
                byte[] vcBytes = Encoding.UTF8.GetBytes(vcWithoutProof);

                proofValue = proofValue.Replace(" ", "").Replace("\n", "").Replace("\r", "");
                byte[] signature;
                try
                {
                    signature = Convert.FromBase64String(proofValue);
                }
                catch (FormatException ex)
                {
                    return BadRequest($"Error: Invalid Base64 string in proofValue: {ex.Message}");
                }

                bool verified;
                if (!string.IsNullOrEmpty(publicKeyMultibase))
                {
                    verified = factory.Verify(publicKeyMultibase, vcBytes, signature);
                }
                else
                {
                    return BadRequest("Error: JWK verification is not supported for this method in the current implementation.");
                }

                return Ok(new
                {
                    Verified = verified,
                    Message = verified ? "The VC is authentic and has not been tampered with." : "The VC is invalid or has been tampered with."
                });
            }
            catch (HttpRequestException ex)
            {
                return StatusCode(500, $"Error resolving DID: {ex.Message}");
            }
            catch (JsonException ex)
            {
                return BadRequest($"Error parsing JSON: {ex.Message}");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error verifying VC: {ex.Message}");
            }
        }

        // Endpoint 5: Tạo VP
        [HttpPost("create-vp")]
        public IActionResult CreateVerifiablePresentation([FromBody] CreateVpRequest request)
        {
            var factory = SignatureFactory.GetFactory(request.Method);
            var contexts = new List<string> { "https://www.w3.org/2018/credentials/v1" };
            if (!contexts.Contains(factory.Context)) contexts.Add(factory.Context);

            var vp = new JObject
            {
                ["@context"] = new JArray(contexts.ToArray()),
                ["type"] = new JArray("VerifiablePresentation"),
                ["verifiableCredential"] = new JArray(request.VerifiableCredentials)
            };

            string vpJson = vp.ToString(Formatting.None);
            byte[] vpBytes = Encoding.UTF8.GetBytes(vpJson);
            byte[] signature = factory.Sign(Convert.FromBase64String(request.PrivateKeyBase64), vpBytes);

            vp["proof"] = new JObject
            {
                ["type"] = factory.ProofType,
                ["created"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                ["verificationMethod"] = $"{request.HolderDid}#{request.Method}",
                ["proofValue"] = Convert.ToBase64String(signature)
            };

            return Ok(vp);
        }

        // Endpoint 6: Xác minh VP
        [HttpPost("verify-vp")]
        public async Task<IActionResult> VerifyVerifiablePresentation([FromBody] VerifyVpRequest request)
        {
            try
            {
                var vp = request.VerifiablePresentation;
                var vpProof = vp["proof"] as JObject;
                if (vpProof == null)
                {
                    return BadRequest("Error: VP does not contain a proof.");
                }

                string vpVerificationMethod = vpProof["verificationMethod"]?.ToString();
                string vpProofValue = vpProof["proofValue"]?.ToString();
                string vpProofType = vpProof["type"]?.ToString();

                if (string.IsNullOrEmpty(vpVerificationMethod) || string.IsNullOrEmpty(vpProofValue) || string.IsNullOrEmpty(vpProofType))
                {
                    return BadRequest("Error: Invalid VP proof format.");
                }

                string vpMethod = vpVerificationMethod.Split('#')[1];
                var vpFactory = SignatureFactory.GetFactory(vpMethod);

                string holderDid = vpVerificationMethod.Split('#')[0];
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Add("Accept", "application/did+ld+json");
                string url = $"https://dev.uniresolver.io/1.0/identifiers/{holderDid}";
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();

                string holderDidDocumentJson = await response.Content.ReadAsStringAsync();
                var holderDidDocument = JObject.Parse(holderDidDocumentJson);

                string vpPublicKeyMultibase = null;
                foreach (var vm in holderDidDocument["verificationMethod"])
                {
                    if (vm["id"]?.ToString() == vpVerificationMethod)
                    {
                        vpPublicKeyMultibase = vm["publicKeyMultibase"]?.ToString();
                        break;
                    }
                }

                if (string.IsNullOrEmpty(vpPublicKeyMultibase))
                {
                    return BadRequest("Error: Could not find holder public key in DID Document.");
                }

                vp.Remove("proof");
                string vpWithoutProof = vp.ToString(Formatting.None);
                byte[] vpBytes = Encoding.UTF8.GetBytes(vpWithoutProof);
                byte[] vpSignature = Convert.FromBase64String(vpProofValue);

                bool vpVerified = vpFactory.Verify(vpPublicKeyMultibase, vpBytes, vpSignature);

                if (!vpVerified)
                {
                    return Ok(new { Verified = false, Message = "The VP signature is invalid or has been tampered with." });
                }

                var verifiableCredentials = vp["verifiableCredential"] as JArray;
                if (verifiableCredentials == null || verifiableCredentials.Count == 0)
                {
                    return BadRequest("Error: VP does not contain any verifiable credentials.");
                }

                foreach (var vc in verifiableCredentials)
                {
                    var vcProof = vc["proof"] as JObject;
                    if (vcProof == null)
                    {
                        return BadRequest("Error: A VC in the VP does not contain a proof.");
                    }

                    string issuerDid = vc["issuer"]?.ToString();
                    string vcVerificationMethod = vcProof["verificationMethod"]?.ToString();
                    string vcProofValue = vcProof["proofValue"]?.ToString();
                    string vcProofType = vcProof["type"]?.ToString();
                    string nonce = vcProof["nonce"]?.ToString();

                    if (string.IsNullOrEmpty(issuerDid) || string.IsNullOrEmpty(vcVerificationMethod) || string.IsNullOrEmpty(vcProofValue) || string.IsNullOrEmpty(vcProofType))
                    {
                        return BadRequest("Error: Invalid VC format in VP.");
                    }

                    string vcMethod = vcVerificationMethod.Split('#')[1];
                    var vcFactory = SignatureFactory.GetFactory(vcMethod);

                    response = await client.GetAsync($"https://dev.uniresolver.io/1.0/identifiers/{issuerDid}");
                    response.EnsureSuccessStatusCode();

                    string issuerDidDocumentJson = await response.Content.ReadAsStringAsync();
                    var issuerDidDocument = JObject.Parse(issuerDidDocumentJson);

                    string vcPublicKeyMultibase = null;
                    foreach (var vm in issuerDidDocument["verificationMethod"])
                    {
                        if (vm["id"]?.ToString() == vcVerificationMethod)
                        {
                            vcPublicKeyMultibase = vm["publicKeyMultibase"]?.ToString();
                            break;
                        }
                    }

                    if (string.IsNullOrEmpty(vcPublicKeyMultibase))
                    {
                        return BadRequest("Error: Could not find issuer public key in DID Document for a VC.");
                    }

    ((JObject)vc).Remove("proof");
                    string vcWithoutProof = vc.ToString(Formatting.None);
                    byte[] vcBytes = Encoding.UTF8.GetBytes(vcWithoutProof);
                    byte[] vcSignature = Convert.FromBase64String(vcProofValue);

                    bool vcVerified;
                    if (vcProofType == "BbsBlsSignatureProof2020")
                    {
                        var credentialSubject = vc["credentialSubject"] as JArray;
                        if (credentialSubject == null)
                        {
                            return BadRequest("Error: credentialSubject must be an array for BBS+ derived proof.");
                        }
                        if (string.IsNullOrEmpty(nonce))
                        {
                            return BadRequest("Error: Nonce missing for BBS+ derived proof.");
                        }

                        vcVerified = vcFactory.VerifyDerivedProof(
                            publicKeyMultibase: vcPublicKeyMultibase,
                            vcBytes: vcBytes,
                            derivedProof: vcSignature,
                            disclosedClaims: credentialSubject.ToObject<List<JObject>>(),
                            nonce: nonce
                        );
                    }
                    else
                    {
                        vcVerified = vcFactory.Verify(vcPublicKeyMultibase, vcBytes, vcSignature);
                    }

                    if (!vcVerified)
                    {
                        return Ok(new { Verified = false, Message = "A VC in the VP is invalid or has been tampered with." });
                    }
                }

                return Ok(new { Verified = true, Message = "The VP and all included VCs are authentic." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error verifying VP: {ex.Message}");
            }
        }

        [HttpPut("update")]
        public IActionResult UpdateDid([FromBody] UpdateDidRequest request)
        {
            try
            {
                string[] didParts = request.Did.Split(':');
                if (didParts.Length < 4 || didParts[0] != "did" || didParts[1] != "web")
                {
                    return BadRequest("Invalid DID format. Expected: did:web:<domain>:<userId>");
                }
                string domain = didParts[2];
                string userId = didParts[3];
                string did = $"did:web:{domain}:{userId}";

                var didDocuments = LoadDidDocuments();

                if (!didDocuments.ContainsKey(did))
                {
                    return NotFound($"DID {did} not found.");
                }

                JObject existingDoc = didDocuments[did];

                var contexts = new HashSet<string>(existingDoc["context"]?.Values<string>() ?? new[] { "https://www.w3.org/ns/did/v1" });
                var verificationMethods = existingDoc["verificationMethod"] as JArray ?? new JArray();
                var authentication = existingDoc["authentication"] as JArray ?? new JArray();

                foreach (var method in request.Methods)
                {
                    var factory = SignatureFactory.GetFactory(method);
                    contexts.Add(factory.Context);

                    var newMethod = new JObject
                    {
                        ["id"] = $"{did}#{method}",
                        ["type"] = factory.ProofType,
                        ["controller"] = did,
                        ["publicKeyMultibase"] = request.PublicKeyMultibases[method]
                    };

                    bool methodExists = false;
                    foreach (var vm in verificationMethods)
                    {
                        if (vm["id"]?.ToString() == $"{did}#{method}")
                        {
                            vm["publicKeyMultibase"] = request.PublicKeyMultibases[method];
                            methodExists = true;
                            break;
                        }
                    }
                    if (!methodExists)
                    {
                        verificationMethods.Add(newMethod);
                        authentication.Add($"{did}#{method}");
                    }
                }

                existingDoc["context"] = new JArray(contexts.ToArray());
                existingDoc["verificationMethod"] = verificationMethods;
                existingDoc["authentication"] = authentication;

                didDocuments[did] = existingDoc;
                SaveDidDocuments(didDocuments);

                return Ok(new { Did = did, DidDocument = existingDoc });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in UpdateDid: {ex.Message}");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPost("sign-data")]
        public IActionResult SignData([FromBody] SignDataRequest request)
        {
            try
            {
                var factory = SignatureFactory.GetFactory(request.Method);
                byte[] dataBytes = Encoding.UTF8.GetBytes(request.Data);
                byte[] privateKey = Convert.FromBase64String(request.PrivateKeyBase64);
                byte[] signature = factory.Sign(privateKey, dataBytes);

                return Ok(new
                {
                    Data = request.Data,
                    Signature = Convert.ToBase64String(signature),
                    Method = request.Method
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in SignData: {ex.Message}");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPost("verify-data")]
        public IActionResult VerifyData([FromBody] VerifyDataRequest request)
        {
            try
            {
                string[] didParts = request.Did.Split(':');
                if (didParts.Length < 4 || didParts[0] != "did" || didParts[1] != "web")
                {
                    return BadRequest("Invalid DID format. Expected: did:web:<domain>:<userId>");
                }
                string userId = didParts[3];
                string did = $"did:web:{didParts[2]}:{userId}";
                string verificationMethodId = $"{did}#{request.Method}";

                var didDocuments = LoadDidDocuments();
                if (!didDocuments.TryGetValue(did, out var didDocument))
                {
                    return NotFound($"DID {did} not found.");
                }

                string publicKeyMultibase = null;
                var verificationMethods = didDocument["verificationMethod"] as JArray;
                if (verificationMethods != null)
                {
                    foreach (var vm in verificationMethods)
                    {
                        if (vm["id"]?.ToString() == verificationMethodId)
                        {
                            publicKeyMultibase = vm["publicKeyMultibase"]?.ToString();
                            break;
                        }
                    }
                }

                if (string.IsNullOrEmpty(publicKeyMultibase))
                {
                    return BadRequest($"Verification method {verificationMethodId} not found in DID Document.");
                }

                var factory = SignatureFactory.GetFactory(request.Method);
                byte[] dataBytes = Encoding.UTF8.GetBytes(request.Data);
                byte[] signature = Convert.FromBase64String(request.Signature);
                bool verified = factory.Verify(publicKeyMultibase, dataBytes, signature);

                return Ok(new
                {
                    Data = request.Data,
                    Signature = request.Signature,
                    Method = request.Method,
                    Did = request.Did,
                    Verified = verified
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in VerifyData: {ex.Message}");
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPost("derive-vc")]
        public IActionResult DeriveVc([FromBody] DeriveVcRequest request)
        {
            try
            {
                var vc = request.VerifiableCredential;
                var factory = SignatureFactory.GetFactory(request.Method);

                // Extract claims from credentialSubject
                var credentialSubject = vc["credentialSubject"] as JArray;
                if (credentialSubject == null)
                {
                    return BadRequest("Error: credentialSubject must be an array.");
                }

                // Validate disclosed indices
                int claimCount = credentialSubject.Count == 1 && credentialSubject[0] is JObject subjectObj
                    ? (subjectObj["id"] != null ? 1 : 0) + (subjectObj["name"] != null ? 1 : 0) + (subjectObj["driver_type"] != null ? 1 : 0)
                    : credentialSubject.Count;
                if (request.DisclosedIndices.Any(i => i < 0 || i >= claimCount))
                {
                    return BadRequest("Error: Invalid disclosed indices.");
                }

                // Get public key from DID document
                string verificationMethod = vc["proof"]?["verificationMethod"]?.ToString();
                if (string.IsNullOrEmpty(verificationMethod))
                {
                    return BadRequest("Error: verificationMethod missing in VC proof.");
                }

                string publicKeyMultibase = request.PublicKeyMultibase;
                if (string.IsNullOrEmpty(publicKeyMultibase))
                {
                    return BadRequest("Error: publicKeyMultibase is required.");
                }

                // Create a new VC with only the disclosed claims
                var disclosedClaims = new JArray();
                if (credentialSubject.Count == 1 && credentialSubject[0] is JObject subjectObj1)
                {
                    var allClaims = new List<JObject>();
                    if (subjectObj1["id"] is JArray idArray && idArray.Count > 0)
                        allClaims.Add(new JObject { ["id"] = idArray[0] });
                    if (subjectObj1["name"] is JArray nameArray && nameArray.Count > 0)
                        allClaims.Add(new JObject { ["name"] = nameArray[0] });
                    if (subjectObj1["driver_type"] is JArray driverTypeArray && driverTypeArray.Count > 0)
                        allClaims.Add(new JObject { ["driver_type"] = driverTypeArray[0] });
                    foreach (var index in request.DisclosedIndices)
                    {
                        if (index < allClaims.Count)
                            disclosedClaims.Add(allClaims[index]);
                    }
                }
                else
                {
                    foreach (var index in request.DisclosedIndices)
                    {
                        disclosedClaims.Add(credentialSubject[index]);
                    }
                }

                var derivedVc = new JObject
                {
                    ["@context"] = vc["@context"],
                    ["id"] = vc["id"],
                    ["type"] = vc["type"],
                    ["issuer"] = vc["issuer"],
                    ["issuanceDate"] = vc["issuanceDate"],
                    ["credentialSubject"] = disclosedClaims
                };

                // Generate derived proof
                string originalProofValue = vc["proof"]?["proofValue"]?.ToString();
                if (string.IsNullOrEmpty(originalProofValue))
                {
                    return BadRequest("Error: Original VC proof is missing.");
                }

                byte[] derivedProof = factory.DeriveProof(
                    originalProof: Convert.FromBase64String(originalProofValue),
                    disclosedIndices: request.DisclosedIndices,
                    credentialSubject: credentialSubject.ToObject<List<JObject>>(),
                    publicKeyMultibase: publicKeyMultibase,
                    nonce: out string nonce
                );

                derivedVc["proof"] = new JObject
                {
                    ["type"] = "BbsBlsSignatureProof2020",
                    ["created"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                    ["verificationMethod"] = verificationMethod,
                    ["proofValue"] = Convert.ToBase64String(derivedProof),
                    ["nonce"] = nonce
                };

                return Ok(derivedVc);
            }
            catch (NotSupportedException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest($"Error deriving VC: {ex.Message}");
            }
        }
    }

    public class GenerateKeyRequest
    {
        public string Method { get; set; }
    }

    public class CreateDidRequest
    {
        public string Did { get; set; }
        public string[] Methods { get; set; }
        public Dictionary<string, string> PublicKeyMultibases { get; set; }
    }

    public class UpdateDidRequest
    {
        public string Did { get; set; }
        public string[] Methods { get; set; }
        public Dictionary<string, string> PublicKeyMultibases { get; set; }
    }

    public class ResolveDidRequest
    {
        public string Did { get; set; }
    }

    public class SignVcRequest
    {
        public string CredentialId { get; set; }
        public string CredentialType { get; set; }
        public string IssuerDid { get; set; }
        public List<JObject> CredentialSubject { get; set; }
        public string Method { get; set; }
        public string PrivateKeyBase64 { get; set; }
    }

    public class VerifyVcRequest
    {
        [Required(ErrorMessage = "VerifiableCredential is required.")]
        public VerifiableCredentialData VerifiableCredential { get; set; }
    }

    public class VerifiableCredentialData
    {
        [Required(ErrorMessage = "Issuer is required.")]
        public string Issuer { get; set; }

        [Required(ErrorMessage = "Proof is required.")]
        public ProofData Proof { get; set; }

        // Optional: context, type, credentialSubject, etc.
        [JsonProperty("@context")]
        public JArray Context { get; set; }

        public JArray Type { get; set; }

        public JObject CredentialSubject { get; set; }

        public string Id { get; set; }

        public string IssuanceDate { get; set; }
    }

    public class ProofData
    {
        [Required(ErrorMessage = "Proof type is required.")]
        public string Type { get; set; }

        [Required(ErrorMessage = "Verification method is required.")]
        public string VerificationMethod { get; set; }

        [Required(ErrorMessage = "Proof value is required.")]
        public string ProofValue { get; set; }

        public string Created { get; set; }
    }

    public class CreateVpRequest
    {
        public string HolderDid { get; set; }
        public List<JObject> VerifiableCredentials { get; set; }
        public string Method { get; set; }
        public string PrivateKeyBase64 { get; set; }
    }

    public class VerifyVpRequest
    {
        public JObject VerifiablePresentation { get; set; }
    }

    public class SignDataRequest
    {
        public string Data { get; set; }
        public string Method { get; set; }
        public string PrivateKeyBase64 { get; set; }
    }

    public class VerifyDataRequest
    {
        public string Data { get; set; }
        public string Signature { get; set; }
        public string Method { get; set; }
        public string Did { get; set; }
    }

    public class DeriveVcRequest
    {
        public JObject VerifiableCredential { get; set; }
        public List<int> DisclosedIndices { get; set; }
        public string HolderDid { get; set; }
        public string Method { get; set; }
        public string PublicKeyMultibase { get; set; }
    }
}