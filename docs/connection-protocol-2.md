# Protocols

- [**Peer-to-Peer Connection Protocol**](#peer-to-peer-connection-protocol)
- [**End-to-End Tunnel Protocol**](#end-to-end-tunnel-protocol)

## Peer-to-Peer Connection Protocol

The protocol used to establish authenticated and encrypted connections between two nodes in a peer-to-peer network. This
is between two nodes only.

- `VerifyNode(Cert, Identifier, Signature[Cert || ...], aad)`:
    - Verifies `Signature[Cert || ...]` using `Cert[PK]`.
    - Verifies `HASH(Cert[PK]) == Identifier`
    - Checks the `aad` signature timestamp is fresh
    - Checks the `aad` target identifier is "my" identifier

1. **Node A**
    - **Node A** generates the ephemeral key pair `(ePKa, eSKa)`
    - **Node A** generates the token `T = RNG(256) || TimeStamp`
    - **Node A** creates a signature `S1 = SIGN(CertA || ePKa, aad=T || TimeStamp() || IdB)`
    - **Node A** sends `ConnectionRequest(T, CertA || ePKa, S1)` to **Node B**
    - **Node A** caches `T`


2. **Node B**, `ConnectionRequest(T', CertA || ePKa, S1)`
    - **Node B** performs `VerifyNode(CertA, IdA, S1, S1-AAD)`
    - **Node B** checks the token timestamp is fresh
    - **Node B** checks `T'` isn't in the token cache, and caches `T'`
    - **Node B** creates a random shared secret `S`
    - **Node B** creates a KEM-wrapped key: `E = ENCAPS(S, ePKa)`
    - **Node B** creates a signature `S2 = SIGN(CertB || E, aad=T' || TimeStamp() || IdA)`
    - **Node B** sends `ConnectionAccept(T', CertB || E, S2)` to **Node A**


3. **Node A**, `ConnectionAccept(T', CertB || E, S2)`
    - **Node A** performs `VerifyNode(CertB, IdB, S2, S2-AAD)`
    - **Node A** computes `S = DECAPS(E, eSKa)`
    - **Node A** computes `H = HASH(E)`
    - **Node A** creates a signature `S3 = SIGN(H, aad=T || TimeStamp() || IdB)`
    - **Node A** sends `ConnectionAcknowledgement(T, H, S3)` to **Node B**


4. **Node B**, `ConnectionAcknowledgement(T', H', S3)`
    - **Node B** performs `VerifyNode(CertA, IdA, S3, S3-AAD)`
    - **Node B** computes `H = HASH(E)`
    - **Node B** verifies `H == H'`


5. **Encrypted, authenticated channel is active**
    - **Node A** and **Node B** derive the encryption key `EK = KDF(S, "EncryptionKey")`

### Algorithms

| What       | Example                                    | Algorithm            |
|------------|--------------------------------------------|----------------------|
| RNG        | `RNG(256)`                                 | `NIST SP 800-90A`    |
| KEM        | `ENCAPS(S, ePK), DECAPS(E, eSK)`           | `CRYSTALS-KYBER`     |
| KDF        | `KDF(S, "EncryptionKey")`                  | `HKDF`               |
| Sign       | `SIGN(msg, sSK, aad), VERIFY(S, sPK, aad)` | `CRYSTALS-DILITHIUM` |
| Hash       | `HASH(msg)`                                | `SHA-3`              |
| Encryption | `ENC(msg, EK), DEC(msg, EK)`               | `AES-OCBv3-256`      |

### Properties

- Mutual authentication:
    - **Node A** authenticates **Node B** using `CertB`
    - **Node B** authenticates **Node A** using `CertA`
    - Both nodes verify future signatures, until the channel is authenticated


- Forward secrecy:
    - The session key `S` is ephemeral and not stored
    - The session key `S` is not derived from the static public keys

#### Man-in-the-middle resistance:

If an intermediary **Node M** tried intercepted **Node A**'s connection request to **Node B** meaningfully, it would
have to pretend to be **Node A**. To trick **Node B** into generating a KEM that **Node M** could decaps, **Node M**
would have to generate the ephemeral key, and sign it. This signature would only be verifiable by **Node M**'s public
key, so **Node M** would have to also switch `CertA` to `CertM`, so **Node B** selects the matching public key. This
would result in **Node B** assuming **Node M** is trying to make a normal connection. However, because signature aad
contains target identifiers, **Node B** would include **Node M**'s identifier in the response. **Node M** would need to
intercept this and change the aad identifier to **Node A**'s identifier, but this would require a signature regeneration
from **Node B**, with the aad identifier set to **Node A**, which isn't possible without **Node B**'s private key, which
**Node M** doesn't have. So **Node M** would need to generate a new signature using its own private key, which would of
course not be verifiable using **Node B**'s public key.

#### Replay resistance:

If **Node M** was to capture a connection request from **Node A** to **Node B**, and then replay it, **Node B** would
see a duplicate cached token, and would reject the request. If **Node M** waited for **Node B**'s cache to expire, and
then replayed the request, **Node B** would see that the timestamp is stale. **Node M** cannot change the timestamp
without causing the signature under **Node A**'s key to fail verification. This means **Node M** cannot replay the
request without **Node A**'s private key, which it doesn't have.

Replaying any other the other connection setup messages will fail, because the connection state of the nodes won't match
for the connection token. For example, if a connection is accepted, a `ConnectionAccept` for the same token is just
ignored. There are no secrets that can be gotten from replaying messages; the only effect (had there not been state
checks) would be to possible cause nodes to crash.

For the e2e encrypted messages once the connection is established, the messages are prepended with a counter, so if a
message is received again, the index will already be set to true, and the message will be ignored. This means that
replaying messages will not cause any issues, and the messages will be ignored.

#### Reflection resistance:

Signature aad includes the target identifier, so any message sent back to the originating node would be discarded.

## End-to-End Tunnel Protocol

The protocol used for a node to establish tunnels to other nodes in the route, via the existing route, without nodes on
the existing route being able to tamper with data being exchanged to set up the tunnels. It is effectively a slimmed
down version of the peer-to-peer connection protocol, with unilateral authentication, to keep the client's identity
hidden from the intermediary nodes.

Assume **Node A** (client) has already established a connection to **Node B** (entry node), using the peer-to-peer
connection protocol. **Node C** has been selected by **Node A** as the next hop in the route.

1. **Node A**
    - **Node A** generates the ephemeral tunnel key pair `(tPKa2c, tSKa2c)`
    - **Node A** generates the token `T = RNG(256) || TimeStamp`
    - **Node A** **cannot** create a signature, otherwise anonymity is broken
    - **Node A** sends `RouteExtension(T, tPKa2c, NodeC)` to **Node B**
    - **Node A** caches `T`


2. **Node B**, `RouteExtension(T, tPKa2c, NodeC)`
    - **Node B** uses the peer-to-peer connection protocol to establish a connection to **Node C**
    - **Node B** sends a `TunnelRequest(T, tPKa2c)` to **Node C**


3. **Node C**, `TunnelRequest(T, tPKa2c)`
    - **Node C** checks the token timestamp is fresh
    - **Node C** checks `T'` isn't in the token cache, and caches `T'`
    - **Node C** creates a random shared secret `S`
    - **Node C** creates a KEM-wrapped key: `E = ENCAPS(S, ePKa)`
    - **Node C** creates a signature `S2 = SIGN(CertC || E || tPKa2c, aad=T' || TimeStamp() || IdB)`
    - **Node C** sends `TunnelAccept(T', CertC || E || tPKa2c, S2)` to **Node A**


3. **Node A**, `TunnelAccept(T', CertC || E || 'tPKa2c, S2)`
    - **Node A** performs `VerifyNode(CertC, IdB, S2, S2-AAD)`
    - **Node A** verifies `tPKa2c == 'tPKa2c`
    - **Node A** computes `S = DECAPS(E, eSKa)`
    

5. **Encrypted, authenticated tunnel is active**
    - **Node A** and **Node C** derive the tunnel encryption key `EK = KDF(S, "TunnelEncryptionKey")`

