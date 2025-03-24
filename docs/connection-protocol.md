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


4. **Node B -> Node A (Connection Confirmation)**
    - Node B computes `H' = Hash(E)`
    - Node B verifies `S3` using `sPKa` (checks `H' = H`)


5. **Encrypted, authenticated channel is active**
    - Nodes derive the encryption key `ek` using `KDF(K, "EncryptionKey") -> ek`
