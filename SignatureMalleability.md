# Signature Malleability article

## Table of Contents
- [Introduction](#introduction)
- [What is signature malleability?](#what-is-signature-malleability)
- [Watch out for this](#watch-out-for-this)
- [Conclusion](#conclusion)
- [Recommendation](#recommendation)
- [References](#references)

## Introduction

The base of this vulnerability stems from a seemingly innocuous [UI issue](https://github.com/ethereum/homestead-guide/blob/master/source/introduction/the-homestead-release.rst) that morphed into a security challenge years down the line. After the Homestead release all transaction signatures with s-values greater than `secp256k1n/2` were considered invalid, but the ECDSA precompile contract did not make this same change.

> "EIP-2/2 fixes a transaction malleability concern (not a security flaw, but a UI inconvenience)."

> "transaction signatures whose s-value is greater than secp256k1n/2 are now considered invalid"

The OpenZeppelin team released a [security advisory](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h) for the issue in 2022. The vulnerability was present in versions of OpenZeppelin contracts >= 4.1.0 < 4.7.3. The fix in 4.7.3 ensures that the library only accepts valid, non-malleable signatures. This vulnerability allowed for signature malleability attacks, where a valid signature could be slightly altered without invalidating it, potentially bypassing signature-based protections. 

Specifically, it affected functions that rely on signature reuse or replay protection, where a user could submit a signature in one form and then resubmit it in a malleable form to bypass the protection. 


## What is signature malleability?

Signature malleability is a cryptographic property where a valid digital signature can be transformed into another valid signature for the same message without knowledge of the private key. In the context of ECDSA (Elliptic Curve Digital Signature Algorithm), which Ethereum uses, this occurs because for any valid signature `(r, s)`, there exists another valid signature `(r, -s mod n)` where `n` is the order of the elliptic curve.

For the secp256k1 curve used by Ethereum, if `s` is a valid signature component, then `secp256k1n - s` is also valid, where `secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`. This means that any signature has two mathematically equivalent forms, creating the malleability issue.

The Homestead hard fork (EIP-2) addressed this at the transaction level by rejecting signatures where `s > secp256k1n/2`, effectively canonicalizing signatures to use only the "low-s" form. However, the `ecrecover` precompile contract continued to accept both high and low s-values, maintaining backward compatibility for applications that might need to verify historical signatures or Bitcoin signatures.

This discrepancy between transaction-level validation and contract-level validation created a vulnerability window where smart contracts using `ecrecover` directly could be susceptible to signature replay attacks in scenarios where the signature itself was used as a unique identifier.


## Watch out for this
1.  A system that performs signature verification on contract level might be susceptible to attacks if the signature is part of the signed message hash. 
    If the system includes the signature in the signed message hash variable, a new hash can be created with the unused s-value allowing it to pass any checks that require uniqueness without invalidating the signature.

    Vulnerable and fixed code described here: [SWC-117](https://swcregistry.io/docs/SWC-117/) (Note: SWC registry is no longer actively maintained since 2020)
    
    [Code comparison showing vulnerable vs fixed signature validation](https://www.diffchecker.com/5MnMLB05/) 

2.  Using ecrecover directly without implementing the checks for valid s-values
    > **⚠️ Warning**: Using `ecrecover` directly without implementing the checks for valid s-values can lead to signature malleability vulnerabilities.

    ```diff
    contract SignatureValidator {
        function isSignatureValid(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (bool) {
    +   require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Invalid 's' value");
    +   require(v == 27 || v == 28, "Invalid 'v' value");
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "Invalid signer");
        return true; // Return true if the address is valid; replace with expected address check
        }
    }
    ```


Vulnerable code example: 
1. `claim()`\
    ![Vulnerable claim() function](https://user-images.githubusercontent.com/35583758/229375957-023d2b02-4bbf-402a-85e5-496fe3dbc243.png)

2. Space and Time (SXT) audit on Cantina
    ```solidity
    function validateMessage(bytes32 message, bytes32[] calldata r, bytes32[] calldata s, uint8[] calldata v)
        external
        view
        returns (bool result)
    {
        ...
        address recoveredAddress = ecrecover(message, v[i], r[i], s[i]);
        ...
    }
    ```

3. [Code comparison showing vulnerable vs fixed signature validation](https://www.diffchecker.com/5MnMLB05/)

## Conclusion

Signature malleability represents a subtle but significant vulnerability that emerged from the intersection of protocol-level improvements and smart contract implementation practices. The Homestead fork's introduction of canonical signature validation at the transaction level, while solving UI inconveniences, inadvertently created a security gap for smart contracts relying on the unchanged `ecrecover` precompile.

The OpenZeppelin vulnerability (CVE-2022-35961) affecting versions 4.1.0 through 4.7.2 demonstrates how this theoretical weakness manifested in real-world applications. The issue particularly impacts systems implementing signature reuse protection or replay prevention mechanisms that mark signatures as used rather than tracking signed message hashes or nonces.

While automated security tools and bots have become proficient at detecting these patterns, the vulnerability underscores the importance of understanding the cryptographic primitives underlying signature verification. For smart contract developers, this serves as a reminder that low-level operations like `ecrecover` require careful handling and validation, particularly when signature uniqueness is a security requirement.

The fix is straightforward but crucial: always validate that `s ≤ 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0` (secp256k1n/2) and `v ∈ {27, 28}` when using `ecrecover` directly, or preferably, use the OpenZeppelin ECDSA library which incorporates these checks by default.

## Recommendation
- Development should take into account the potential for signature malleability attacks, especially when using ECDSA signatures. Account for the possibility of multiple values for the same signature and ensure that the system can handle these variations without compromising security.

- Use the latest versions of OpenZeppelin's ECDSA library instead of relying on the ecrecover() precompile entirely. Fixed in newer versions of ECDSA >= 4.7.3
https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol#L134

## References
- [EIP-2: Homestead Hard-fork Changes](https://eips.ethereum.org/EIPS/eip-2)

- [Ethereum Homestead Release Documentation](https://github.com/ethereum/homestead-guide/blob/master/source/introduction/the-homestead-release.rst)

- [OpenZeppelin Security Advisory GHSA-4h98-2769-gh6h](https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h)

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

- [Bitcoin BIP-62: Dealing with Transaction Malleability](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki)

- [Safeguarding Solidity's ecrecover Against Signature Malleability](https://medium.com/@joichiro.sai/safeguarding-soliditys-ecrecover-against-signature-malleability-5debfdd481f4)
