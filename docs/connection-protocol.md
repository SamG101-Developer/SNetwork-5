# Protocols

## Peer-to-Peer Connection Protocol

The protocol used to establish authenticated and encrypted connections between two nodes in a peer-to-peer network. This
is between two nodes only.

1. **Node A -> Node B (Connection Request)**
    - Node A generates the connection token `T = RNG(256) || TimeStamp`
    - Node A generates the ephemeral key pair `(ePKa, eSKa)`
    - Node A signs `S1 = Sign(ePKa || T || IDb, sSKa)`
    - Node A sends `ConnectionRequest(T, ePKa, cert_a, S1)` to Node B


2. **Node B -> Node A (Connection Accept)**
    - Node B verifies `cert_a` and `S1` using `sPKa`
    - Node B generates session key `K` (CSRNG)
    - Node B encapsulates `K` using `E = KEM(K, ePKa)`
    - Node B signs `S2 = Sign(E || T || IDa, sSKb)`
    - Node B sends `ConnectionAccept(T, E, S2)` to Node A


3. **Node A -> Node B (Connection Acknowledgement)**
    - Node A verifies `S2` using `sPKb` (checks `T = T'`)
    - Node A decapsulates `E` using `K = UNKEM(E, eSKa)`
    - Node A computes `H = Hash(E)`
    - Node A signs `S3 = Sign(H || T || IDb, sSKa)`
    - Node A sends `ConnectionAcknowledgement(H, S3)` to Node B


4. **Node B final verification**
    - Node B computes `H' = Hash(E)`
    - Node B verifies `S3` using `sPKa` (checks `H' = H`)


5. **Encrypted, authenticated channel is active**
    - Nodes derive the encryption key `ek` using `KDF(K, "EncryptionKey") -> ek`

## End-to-End Tunnel Protocol

The protocol used for a node to establish tunnels to other nodes in the route, via the existing route, without nodes on
the existing route being able to tamper with data being exchanged to set up the tunnels.

1. **Node A establishes connection to Node B**
    - Use the [](#peer-to-peer-connection-protocol) to establish a connection to Node B.
    - This will create a secure channel between Node A and Node B.


2. **Node A sends a route extension to Node B with Node C's information.**
    - Node A generates a new ephemeral tunnel key pair `(tPKac, tSKac)`
    - Node A generates a new tunnel token `T = RNG(256) || TimeStamp`
    - Node A cannot sign anything, otherwise anonymity is broken.
    - Node A sends `RouteExtension(T, tPKac)` to Node B.
    - Node B uses the [](#peer-to-peer-connection-protocol) to establish a connection to Node C.
    - Node B sends `TunnelRequest(T, tPKac)` to Node C.


3. **Node C receives the tunnel request from Node B**
    - Node C generates session key `K` (CSRNG)
    - Node C encapsulates `K` using `E = KEM(K, tPKac)`
    - Node C signs `S2 = Sign(E || T || tPKac || IDb, sSKc)`
    - Node C sends `TunnelAccept(T, E, S2, cert_c)` to Node A (via Node B)
    - **Reverse tunnelling is used, so when Node D is connected too, Node B won't know who they are.**


4. **Node A receives the tunnel accept from Node C**
    - Node A verifies `S2` using `sPKc` (checks `T = T'`, `tPKac = tPKac'`)
    - Node A decapsulates `E` using `K = UNKEM(E, tSKac)`
