---
title: Composite Signatures For Use In Internet PKI
abbrev: PQ Composite Sigs
# <!-- EDNOTE: Edits the draft name -->
docname: draft-ounsworth-pq-composite-sigs-09

# <!-- stand_alone: true -->
ipr: trust200902
area: Security
wg: LAMPS
kw: Internet-Draft
cat: std

coding: us-ascii
pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
    -
      ins: M. Ounsworth
      name: Mike Ounsworth
      org: Entrust Limited
      abbrev: Entrust
      street: 2500 Solandt Road – Suite 100
      city: Ottawa, Ontario
      country: Canada
      code: K2K 3G5
      email: mike.ounsworth@entrust.com

    -
      ins: J. Gray
      name: John Gray
      org: Entrust Limited
      abbrev: Entrust
      street: 2500 Solandt Road – Suite 100
      city: Ottawa, Ontario
      country: Canada
      code: K2K 3G5
      email: john.gray@entrust.com

    -
      ins: M. Pala
      name: Massimiliano Pala
      org: CableLabs
      email: director@openca.org
      abbrev: CableLabs
      street: 858 Coal Creek Circle
      city: Louisville, Colorado
      country: United States of America
      code: 80027  
      
  
normative:
  RFC2119:
  RFC2986:
  RFC4210:
  RFC5280:
  RFC5480:
  RFC5639:
  RFC5652:
  RFC6090:
  RFC7748:
  RFC8174:
  RFC8410:
  RFC8411:
  I-D.draft-ounsworth-pq-composite-keys-04:
  I-D.draft-massimo-lamps-pq-sig-certificates-00:
  I-D.draft-ietf-lamps-dilithium-certificates-01:
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015


# <!-- EDNOTE: full syntax for this defined here: https://github.com/cabo/kramdown-rfc2629 -->

informative:
  RFC3279:
  RFC7296:
  RFC8446:
  RFC8551:
  RFC8017:
  I-D.draft-ounsworth-pq-composite-kem-00:
  I-D.draft-becker-guthrie-noncomposite-hybrid-auth-00:
  I-D.draft-guthrie-ipsecme-ikev2-hybrid-auth-00:
  I-D.draft-pala-klaussner-composite-kofn-00:
  Bindel2017:
    title: "Transitioning to a quantum-resistant public key infrastructure"
    target: "https://link.springer.com/chapter/10.1007/978-3-319-59879-6_22"
    author:
      -
        ins: N. Bindel
        name: Nina Bindel
      -
        ins: U. Herath
        name: Udyani Herath
      -
        ins: M. McKague
        name: Matthew McKague
      -
        ins: D. Stebila
        name: Douglas Stebila
    date: 2017


--- abstract

The migration to post-quantum cryptography is unique in the history of modern digital cryptography in that neither the old outgoing nor the new incoming algorithms are fully trusted to protect data for the required data lifetimes. The outgoing algorithms, such as RSA and elliptic curve, may fall to quantum cryptanalysis, while the incoming post-quantum algorithms face uncertainty about both the underlying mathematics as well as hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

Cautious implementers may wish to layer cryptographic algorithms such that an attacker would need to break all of them in order to compromise the data being protected using either a Post-Quantum / Traditional Hybrid, Post-Quantum / Post-Quantum Hybrid, or combinations thereof. This document, and its companions, defines a specific instantiation of hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key, signature, or key encapsulation mechanism (KEM) such that they can be treated as a single atomic object at the protocol level.

This document defines the structures CompositeSignatureValue, and CompositeSignatureParams, which are sequences of the respective structure for each component algorithm. The explicit variant is defined which allows for a set of signature algorithm identifier OIDs to be registered together as an explicit composite signature algorithm and assigned an OID. 


This document is intended to be coupled with corresponding documents that define the structure and semantics of composite public and private keys and encryption {{I-D.ounsworth-pq-composite-keys}}, however may also be used with non-composite keys, such as when a protocol combines multiple certificates into a single cryptographic operation.

<!-- End of Abstract -->


--- middle

# Changes in version -09

* Removed SPHINCS+ hybrids.
* Removed all references to generic composite.
* Added selection criteria note about requesting new explicit combinations.


# Introduction {#sec-intro}

During the transition to post-quantum cryptography, there will be uncertainty as to the strength of cryptographic algorithms; we will no longer fully trust traditional cryptography such as RSA, Diffie-Hellman, DSA and their elliptic curve variants, but we will also not
   fully trust their post-quantum replacements until they have had sufficient scrutiny and time to discover and fix implementation bugs. Unlike previous cryptographic algorithm migrations, the choice of when to migrate and which algorithms to migrate to, is not so clear. Even after the migration period, it may be advantageous for an entity's cryptographic identity to be composed of multiple public-key algorithms.

The deployment of composite signatures using post-quantum algorithms will face two challenges

- *Algorithm strength* uncertainty: During the transition period, some post-quantum signature and encryption algorithms will not be fully trusted, while also the trust in legacy public key algorithms will start to erode.  A relying party may learn some time after deployment that a public key algorithm has become untrustworthy, but in the interim, they may not know which algorithm an adversary has compromised.
- *Backwards compatibility*: During the transition period, post-quantum algorithms will not be supported by all clients.

This document provides a mechanism to address algorithm strength uncertainty concerns by building on {{I-D.ounsworth-pq-composite-keys}} by providing formats for encoding multiple signature values into existing public signature fields, as well as the process for validating a composite signature. Backwards compatibility is addressed via using composite in conjunction with a non-composite hybrid mode such as that described in {{I-D.becker-guthrie-noncomposite-hybrid-auth}}.

This document is intended for general applicability anywhere that digital signatures are used within PKIX and CMS structures.


## Algorithm Selection Criteria

The composite algorithm combinations defined in this document were chosen according to the following guidelines:

1. A single RSA combination is provided (but RSA modulus size not mandated), matched with NIST PQC Level 3 algorithms.
1. Elliptic curve algorithms are provided with combinations on each of the NIST [RFC6090], Brainpool [RFC5639], and Edwards [RFC7748] curves. NIST PQC Levels 1 - 3 algorithms are matched with 256-bit curves, while NIST levels 4 - 5 are matched with 384-bit elliptic curves. This provides a balance between matching classical security levels of post-quantum and traditional algorithms, and also selecting elliptic curves which already have wide adoption.
1. NIST level 1 candidates (Falcon512 and Kyber512) are provided, matched with 256-bit elliptic curves, intended for constrained use cases.
The authors wish to note that although all the composite structures defined in this and the companion documents {{I-D.ounsworth-pq-composite-keys}} and {{I-D.ounsworth-pq-composite-kem}} specifications are defined in such a way as to easily allow 3 or more component algorithms, it was decided to only specify explicit pairs. This also does not preclude future specification of explicit combinations with three or more components.

To maximize interoperability, use of the specific algorithm combinations specified in this document is encouraged.  If other combinations are needed, a separate specification should be submitted to the IETF LAMPS working group.  To ease implementation, these specifications are encouraged to follow the construction pattern of the algorithms specified in this document.  


## Terminology {#sec-terminology}
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}  {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

The following terms are used in this document:

ALGORITHM:
          A standardized cryptographic primitive, as well as 
          any ASN.1 structures needed for encoding data and 
          metadata needed to use the algorithm. This document is
          primarily concerned with algorithms for producing digital
          signatures.

BER:
          Basic Encoding Rules (BER) as defined in [X.690].

CLIENT:
          Any software that is making use of a cryptographic key.
          This includes a signer, verifier, encrypter, decrypter.

COMPONENT ALGORITHM:
          A single basic algorithm which is contained within a
            composite algorithm.

COMPOSITE ALGORITHM:
          An algorithm which is a sequence of two or more component
            algorithms, as defined in {{sec-composite-structs}}.

DER:
          Distinguished Encoding Rules as defined in [X.690].

LEGACY:   For the purposes of this document, a legacy algorithm is
          any cryptographic algorithm currently in use which is 
          not believed to be resistant to quantum cryptanalysis.

PKI:
          Public Key Infrastructure, as defined in [RFC5280].

POST-QUANTUM ALGORITHM:
          Any cryptographic algorithm which is believed to be resistant
          to classical and quantum cryptanalysis, such as the algorithms being considered for standardization by NIST.

PUBLIC / PRIVATE KEY:
          The public and private portion of an asymmetric cryptographic
            key, making no assumptions about which algorithm.

SIGNATURE:
          A digital cryptographic signature, making no assumptions
            about which algorithm.

STRIPPING ATTACK:
          An attack in which the attacker is able to downgrade the 
          cryptographic object to an attacker-chosen subset of
          original set of component algorithms in such a way that
          it is not detectable by the receiver. For example, 
          substituting a composite public key or signature for a
          version with fewer components.


<!-- End of Introduction section -->


# Composite Signature Structures {#sec-composite-structs}

In order for signatures to be composed of multiple algorithms, we define encodings consisting of a sequence of signature primitives (aka "component algorithms") such that these structures can be used as a drop-in replacement for existing signature fields such as those found in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652].


## Composite Keys

A composite signature MAY be associated with a composite public key as defined in {{I-D.ounsworth-pq-composite-keys}}, but MAY also be associated with multiple public keys from different sources, for example multiple X.509 certificates, or multiple cryptographic modules. In the latter case, composite signatures MAY be used as the mechanism for carrying multiple signatures in a non-composite hybrid authentication mechanism such as those described in {{I-D.becker-guthrie-noncomposite-hybrid-auth}}.


### Key Usage Bits

For protocols such as X.509 [RFC5280] that specify key usage along with the public key, then the composite public key associated with a composite signature MUST have a signing-type key usage.


If the keyUsage extension is present in a Certification Authority (CA) certificate that indicates a composite key, then any combination of the following values MAY be present:

~~~
digitalSignature;
nonRepudiation;
keyCertSign; and
cRLSign.
~~~

If the keyUsage extension is present in an End Entity (EE) certificate that indicates a composite key, then any combination of the following values MAY be present:

~~~
digitalSignature; and
nonRepudiation;
~~~

## sa-CompositeSignature {#sec-composite-sig-structs}

The ASN.1 algorithm object for a composite signature is:

~~~ asn.1
sa-CompositeSignature SIGNATURE-ALGORITHM ::= {
    IDENTIFIER TYPE OBJECT IDENTIFIER
    VALUE CompositeSignatureValue
    PARAMS ANY DEFINED BY ALGORITHM
    PUBLIC-KEYS { pk-Composite }
    SMIME-CAPS ANY DEFINED BY ALGORITHM }
~~~


The following is an explanation how SIGNATURE-ALGORITHM elements are used 
to create Composite Signatures:

| SIGNATURE-ALGORITHM element | Definition | 
| ---------                  | ---------- |
| IDENTIFIER                  | The Object ID used to identify the composite Signature Algorithm | 
| VALUE                       | The Sequence of BIT STRINGS for each component signature value | 
| PARAMS                      | Signature parameters either declared ABSENT, or defined with a type and encoding | 
| PUBLIC-KEYS                 | The composite key required to produce the composite signature | 
| SMIME_CAPS                  | Not needed for composite | 



## CompositeSignatureValue {#sec-compositeSignatureValue}

The output of the composite signature algorithm is the DER encoding of the following structure:

~~~ asn.1
CompositeSignatureValue ::= SEQUENCE SIZE (2..MAX) OF BIT STRING
~~~
{: artwork-name="composite-sig-asn.1"}

Where each BIT STRING within the SEQUENCE is a signature value produced by one of the component keys. It MUST contain one signature value produced by each component algorithm, and in the same order as in the associated CompositeSignatureParams object.

A CompositeSignatureValue MUST contain the same number of component signatures as the corresponding public and private keys, and the order of component signature values MUST correspond to the component public keys.

The choice of `SEQUENCE OF BIT STRING`, rather than for example a single BIT STRING containing the concatenated signature values, is to gracefully handle variable-length signature values by taking advantage of ASN.1's built-in length fields.


## CompositeSignatureParameters {#sec-compositeParameters}

Composite signature parameters are defined as follows and MAY be used when a composite signature is used with an AlgorithmIdentifier:

~~~ asn.1
CompositeSignatureParams ::= SEQUENCE SIZE (2..MAX) OF  
     AlgorithmIdentifier{SIGNATURE-ALGORITHM, {SignatureAlgSet}}
~~~
{: artwork-name="CompositeSignatureParams-asn.1-structures"}

The signature's CompositeSignatureParams sequence MUST contain the same component algorithms listed in the same order as in the associated CompositePublicKey.  

For explicit algorithms, it is not strictly necessary to carry a CompositeSignatureParams with the list of component algorithms in the signature algorithm parameters because clients can infer the expected component algorithms from the algorithm identifier. The PARAMS is left optional because some types of component algorithms will require parameters to be carried, such as RSASSA-PSS-params as defined in [RFC8017]. {{sec-composite-sig-structs}} defines `PARAMS ANY DEFINED BY ALGORITHM` so that explicit algorithms may define params as ABSENT, or use `CompositeSignatureParams` as defined in ASN.1 module.  


## Encoding Rules {#sec-encoding-rules}
<!-- EDNOTE 7: Examples of how other specifications specify how a data structure is converted to a bit string can be found in RFC 2313, section 10.1.4, 3279 section 2.3.5, and RFC 4055, section 3.2. -->

Many protocol specifications will require that composite signature data structures be represented by an octet string or bit string.

When an octet string is required, the DER encoding of the composite data structure SHALL be used directly.

When a bit string is required, the octets of the DER encoded composite data structure SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

In the interests of simplicity and avoiding compatibility issues, implementations that parse these structures MAY accept both BER and DER.

# Algorithm Identifiers {#sec-alg-ids}

This section defines the algorithm identifiers for explicit combinations.  For simplicity and prototyping purposes, the signature algorithm object identifiers specified in this document are the same as the composite key object Identifiers specified in {draft-ounsworth-pq-composite-keys}.  A proper implementation should not presume that the object ID of a composite key will be the same as its composite signature algorithm.   

This section is not intended to be exhaustive and other authors may define other composite signature algorithms so long as they are compatible with the structures and processes defined in this and companion public and private key documents.

Some use-cases desire the flexibility for clients to use any combination of supported algorithms, while others desire the rigidity of explicitly-specified combinations of algorithms.

The following table summarizes the details for each explicit composite signature algorithms:


The OID referenced are TBD for prototyping only, and the following prefix is used for each:

replace &lt;CompSig&gt; with the String "2.16.840.1.114027.80.5.1"

Therefore &lt;CompSig&gt;.1 is equal to 2.16.840.1.114027.80.5.1.1 

Signature public key types:

| Composite Signature AlgorithmID | OID | First Algorithm | Second Algorithm | 
| ----------- | ----------- | ----------- |  ----------- | 
| id-Dilithium3-RSA-PSS                      | &lt;CompSig&gt;.14 | Dilithium3 | SHA256WithRSAPSS | 
| id-Dilithium3-RSA-PKCS15-SHA256            | &lt;CompSig&gt;.1  | Dilithium3 | SHA256WithRSAEncryption |
| id-Dilithium3-ECDSA-P256-SHA256            | &lt;CompSig&gt;.2  | Dilithium3 | SHA256withECDSA | 
| id-Dilithium3-ECDSA-brainpoolP256r1-SHA256 | &lt;CompSig&gt;.3  | Dilithium3 | SHA256withECDSA |  
| id-Dilithium3-Ed25519                      | &lt;CompSig&gt;.4  | Dilithium3 | Ed25519 | 
| id-Dilithium5-ECDSA-P384-SHA384            | &lt;CompSig&gt;.5  | Dilithium5 | SHA384withECDSA | 
| id-Dilithium5-ECDSA-brainpoolP384r1-SHA384 | &lt;CompSig&gt;.6  | Dilithium5 | SHA384withECDSA | 
| id-Dilithium5-Ed448                        | &lt;CompSig&gt;.7  | Dilithium5 | Ed448 | 
| id-Falcon512-ECDSA-P256-SHA256             | &lt;CompSig&gt;.8  | Falcon512  | SHA256withECDSA | 
| id-Falcon512-ECDSA-brainpoolP256r1-SHA256  | &lt;CompSig&gt;.9  | Falcon512  | SHA256withECDSA | 
| id-Falcon512-Ed25519                       | &lt;CompSig&gt;.10 | Falcon512  | Ed25519| 
{: #tab-composite-sigs title="Explicit Composite Signature Algorithms"}

The table above contains everything needed to implement the listed explicit composite algorithms. See the ASN.1 module in section {{sec-asn1-module}} for the explicit definitions of the above Composite signature algorithms.   


Full specifications for the referenced algorithms can be found as follows:

* _Dilithium_: {{I-D.ietf-lamps-dilithium-certificates}}
* _ECDSA_: [RFC5480]
* _Ed25519 / Ed448_: [RFC8410]
* _Falcon_: TBD
* _RSAES-PKCS-v1_5_: [RFC8017]
* _RSASSA-PSS_: [RFC8017]


## Notes on id-Dilithium3-RSA-PSS

Use of RSA-PSS [RFC8017] deserves a special explanation.

When the `id-Dilithium3-RSA-PSS` object identifier is used with an `AlgorithmIdentifier`, the `AlgorithmIdentifier.parameters` MUST be of type `CompositeSignatureParams` as follows:

~~~
SEQUENCE {
    AlgorithmIdentifier {
        id-Dilithium3TBD
    },
    AlgorithmIdentifier {
        id-RSASSA-PSS,
        RSASSA-PSS-params
    }
}
~~~

EDNOTE: We probably should pick concrete crypto for the `RSASSA-PSS-params`. Once the crypto is fixed, we could omit the parameters entirely and expect implementations to re-constitute the params structures as necessary in order to call into lower-level crypto libraries.

TODO: there must be a way to put all this the ASN.1 Module rather than just specifying it as text?


# Composite Signature Processes {#sec-composite-signature-algorithm}

This section specifies the processes for generating and verifying composite signatures.

This process addresses algorithm strength uncertainty by providing the verifier with parallel signatures from all the component signature algorithms; thus forging the composite signature would require forging all of the component signatures.

## Composite Signature Generation Process {#sec-comp-sig-gen}

Generation of a composite signature involves applying each component algorithm's signature process to the input message according to its specification, and then placing each component signature value into the CompositeSignatureValue structure defined in {{sec-composite-sig-structs}}.

The following process is used to generate composite signature values.

~~~
Input:
     K1, K2, .., Kn     Signing private keys. See note below on 
                        composite inputs.

     A1, A2, ... An     Component signature algorithms. See note below on 
                        composite inputs.

     M                  Message to be signed, an octet string

Output:
     S                  The signatures, a CompositeSignatureValue

Signature Generation Process:
   1. Generate the n component signatures independently,
      according to their algorithm specifications.

        for i := 1 to n
            Si := Sign( Ki, Ai, M )

   2. Encode each component signature S1, S2, .., Sn into a BIT STRING
      according to its algorithm specification.

        S ::= Sequence { S1, S2, .., Sn }

   3. Output S
~~~
{: artwork-name="alg-composite-sig-gen"}

Note on composite inputs: the method of providing the list of component keys and algorithms is flexible and beyond the scope of this pseudo-code, for example they may be carried in CompositePrivateKey and CompositeSignatureParams structures. It is also possible to generate a composite signature that combines signatures from distinct keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this document so long as it produces the same output as the process sketched above.

Since recursive composite public keys are disallowed in {{I-D.ounsworth-pq-composite-keys}}, no component signature may itself be a composite; ie the signature generation process MUST fail if one of the private keys K1, K2, .., Kn is a composite with the OID id-alg-composite or an explicit composite OID.

A composite signature MUST produce, and include in the output, a signature value for every component key in  and include in the output, a signature value for every component key in the corresponding CompositePublicKey, and they MUST be in the same order; ie in the output, S1 MUST correspond to K1, S2 to K2, etc. 


## Composite Signature Verification Process {#sec-comp-sig-verify}

Verification of a composite signature involves applying each component algorithm's verification process according to its specification.

In the absence of an application profile specifying otherwise, compliant applications MUST output "Valid signature" (true) if and only if all component signatures were successfully validated, and "Invalid signature" (false) otherwise.

The following process is used to perform this verification.


~~~
Input:
     P1, P2, .., Pn     Public verification keys. See note below on 
                        composite inputs.

     M                  Message whose signature is to be verified, 
                        an octet string.
     
     S1, S2, .., Sn    Component signature values to be verified.
                       See note below on composite inputs.
     
     A1, A2, ... An     Component signature algorithms. See note 
                        below on composite inputs.

Output:
    Validity (bool)    "Valid signature" (true) if the composite 
                        signature is valid, "Invalid signature" 
                        (false) otherwise.

Signature Verification Procedure::
   1. Check keys, signatures, and algorithms lists for consistency.

      If Error during Desequencing, or the three sequences have
      different numbers of elements, or any of the public keys 
      P1, P2, .., Pn or algorithm identifiers A1, A2, .., An are 
      composite with the OID id-alg-composite or an explicit composite
      OID then output "Invalid signature" and stop.

   2. Check each component signature individually, according to its
       algorithm specification.
       If any fail, then the entire signature validation fails.

     for i := 1 to n
          if not verify( Pi, M, Si, Ai ), then
            output "Invalid signature"

      if all succeeded, then
        output "Valid signature"
~~~
{: artwork-name="alg-sig-verif"}

Note on composite inputs: the method of providing the list of component keys, algorithms and signatures is flexible and beyond the scope of this pseudo-code, for example they may be carried in CompositePublicKey, CompositeSignatureParams, and CompositeSignatureValue structures. It is also possible to verify a composite signature where the component public verification keys belong, for example, to separate X.509 certificates or cryptographic modules. Variations in the process to accommodate particular public verification key storage mechanisms are considered to be conformant to this document so long as it produces the same output as the process sketched above.

Since recursive composite public keys are disallowed in {{I-D.ounsworth-pq-composite-keys}}, no component signature may be composite; ie the signature verification procedure MUST fail if any of the public keys P1, P2, .., Pn or algorithm identifiers A1, A2, .., An are composite with OID id-alg-composite or an explicit composite OID.

Some verification clients may include a policy mechanism for specifying acceptable subsets of algorithms. In these cases, implementer MAY, in the interest of performance of compatibility, modify the above process to skip one or more signature validations as per their local client policy. See {{I-D.pala-klaussner-composite-kofn}} for a discussion of implementation and associated risks.

<!-- End of Composite Signature Algorithm section -->


# ASN.1 Module {#sec-asn1-module}

~~~ asn.1

<CODE STARTS>

!!  Composite-Signatures-2023.asn
 
<CODE ENDS>

~~~



# IANA Considerations {#sec-iana}

This document registers the following in the SMI "Security for PKIX Algorithms (1.3.6.1.5.5.7.6)" registry:

~~~
id-alg-composite OBJECT IDENTIFIER ::= {
    iso(1) identified-organization(3) dod(6) internet(1) security(5)
    mechanisms(5) pkix(7) algorithms(6) composite(??) }
~~~

Plus the ASN.1 Module OID for `Composite-Signatures-2023`.

<!-- End of IANA Considerations section -->


# Security Considerations

## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key, certificate, or signature contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), then clients performing signatures or verifications should be updated to adhere to appropriate policies.

In the composite model this is less obvious since a single public key, certificate, or signature may contain a mixture of deprecated and non-deprecated algorithms. Moreover, implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though neither algorithm is acceptable by itself.

Specifying a modified verification algorithm to handle these situations is beyond the scope of this draft, but could be desirable as the subject of an application profile document, or to be up to the discretion of implementers.

~~~
2. Check policy to see whether A1, A2, ..., An constitutes a valid
   combination of algorithms.

   if not checkPolicy(A1, A2, ..., An), then
     output "Invalid signature"
~~~


<!-- End of Security Considerations section -->


<!-- Start of Appendices -->

--- back

# Work in Progress

## Combiner modes (KofN)

For content commitment use-cases, such as legally-binding non-repudiation, the signer (whether it be a CA or an end entity) needs to be able to specify how its signature is to be interpreted and verified.

For now we have removed combiner modes (AND, OR, KofN) from this draft, but we are still discussing how to incorporate this for the cases where it is needed (maybe a X.509 v3 extension, or a signature algorithm param).



# Samples {#appdx-samples}

## Explicit Composite Signature Examples {#appdx-expComposite-examples}

TODO



# Implementation Considerations {#sec-imp-considers}

This section addresses practical issues of how this draft affects other protocols and standards.


## Backwards Compatibility {#sec-backwards-compat}

The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can interoperate with the upgraded systems of the future.  This draft explicitly does not provide backwards compatibility, only upgraded systems will understand the OIDs defined in this document.

If backwards compatibility is required, then additional mechanisms will be needed.  Migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to digital signature objects, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], document signing such as in the context of the European eIDAS regulations [eIDAS2014], and publicly trusted code signing [codeSigningBRsv2.8], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] signed structures.  Composite simplifies the protocol design work because it can be implemented as a signature algorithm that fits into existing systems.


### Parallel PKIs

We present the term "Parallel PKI" to refer to the setup where a PKI end entity possesses two or more distinct public keys or certificates for the same identity (name), but containing keys for different cryptographic algorithms. One could imagine a set of parallel PKIs where an existing PKI using legacy algorithms (RSA, ECC) is left operational during the post-quantum migration but is shadowed by one or more parallel PKIs using pure post quantum algorithms or composite algorithms (legacy and post-quantum).

Equipped with a set of parallel public keys in this way, a client would have the flexibility to choose which public key(s) or certificate(s) to use in a given signature operation. 

For negotiated protocols, the client could choose which public key(s) or certificate(s) to use based on the negotiated algorithms, or could combine two of the public keys for example in a non-composite hybrid method such as {{I-D.becker-guthrie-noncomposite-hybrid-auth}} or {{I-D.guthrie-ipsecme-ikev2-hybrid-auth}}. Note that it is possible to use the signature algorithms defined in {{sec-alg-ids}} as a way to carry the multiple signature values generated by one of the non-composite public mechanism in protocols where it is easier to support the composite signature algorithms than to implement such a mechanism in the protocol itself. There is also nothing precluding a composite public key from being one of the components used within a non-composite authentication operation; this may lead to greater convenience in setting up parallel PKI hierarchies that need to service a range of clients implementing different styles of post-quantum migration strategies.

For non-negotiated protocols, the details for obtaining backwards compatibility will vary by protocol, but for example in CMS [RFC5652], the inclusion of multiple SignerInfo objects is often already treated as an OR relationship, so including one for each of the signer's parallel PKI public keys would, in many cases, have the desired effect of allowing the receiver to choose one they are compatible with and ignore the others, thus achieving full backwards compatibility.

### Hybrid Extensions (Keys and Signatures)
The use of Composite Crypto provides the possibility to process multiple algorithms without changing the logic of applications, but updating the cryptographic libraries: one-time change across the whole system. However, when it is not possible to upgrade the crypto engines/libraries, it is possible to leverage X.509 extensions to encode the additional keys and signatures. When the custom extensions are not marked critical, although this approach provides the most
backward-compatible approach where clients can simply ignore the post-quantum (or extra) keys and signatures, it also requires
all applications to be updated for correctly processing multiple algorithms together. 


<!-- End of Implementation Considerations section -->



# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/



# Contributors and Acknowledgements
This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past year in pursuit of this document:

Serge Mister (Entrust),
Scott Fluhrer (Cisco Systems),
Panos Kampanakis (Cisco Systems),
Daniel Van Geest (ISARA),
Tim Hollebeek (Digicert), and
François Rousseau.

We are grateful to all, including any contributors who may have
been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].

## Making contributions

Additional contributions to this draft are welcome. Please see the working copy of this draft at, as well as open issues at:

https://github.com/EntrustCorporation/draft-ounsworth-composite-sigs

<!-- End of Contributors section -->
