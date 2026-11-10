# WideConnect Pairing & Authentication v1

## Goals

- Only devices the user has explicitly paired can use features (notify, files, screen).
- Pairing is confirmed by a human comparing a short code on both screens.
- After pairing, every connection re-proves identity cryptographically.
- No third-party dependencies: Go stdlib `crypto/ed25519` and `crypto/sha256`.

## Threat model

Tailscale provides an encrypted, node-authenticated tunnel. We assume it works,
but we do NOT trust every peer on the tailnet. Out of scope: a compromised
paired device, and attackers who can already read the memory of a device.

## Identity (replaces the random DeviceID from v1)

Each device has a long-term Ed25519 keypair, generated once and stored in
identity.json (file mode 0600).

    DeviceID = SHA-256(public key)[:16]

Binding the ID to the key means a peer cannot claim someone else's ID without
their private key. identity.json moves to version 2 and gains a private_key field.

## Pairing flow (three frames, then a human decision)

A = initiator, B = responder. Nonces are 16 random bytes.

1. A -> B  PAIR_REQUEST   commitment = SHA-256(pubA || nonceA)
2. B -> A  PAIR_RESPONSE  pubB (32) || nonceB (16)
3. A -> B  PAIR_REVEAL    pubA (32) || nonceA (16)
   B checks the reveal matches the commitment, else aborts.

Both sides now compute the same 6-digit code:

    h    = SHA-256("WC-PAIR-v1" || pubA || pubB || nonceA || nonceB)
    code = (first 4 bytes of h as big-endian uint32) mod 1,000,000, zero-padded

Each user compares the code on both screens.

4. The initiator sends PAIR_DECISION first (1 = accept, 0 = reject).
   - If it is 0, the pairing is over. The responder sends nothing.
   - If it is 1, the responder answers with its own PAIR_DECISION.
   A device is stored only if BOTH decisions are 1. A user who does not
   decide within 60 seconds counts as rejecting.

Checks that abort the pairing:

- The revealed key and nonce do not match the earlier commitment.
- The peer presents our own public key.
- SHA-256(peer public key)[:16] is not the DeviceID the peer sent in its HELLO.
- Any frame other than the expected next one arrives (for example PING
  during pairing), or a payload has the wrong length.

Pairing does not prove that the peer holds the private key. The first AUTH
exchange after pairing does: a peer that paired with a key it does not own
cannot sign the challenge.

## Storage: paired.json (same directory as identity.json)

A versioned list of { device_id, name, public_key, paired_at }.
A device is "paired" if its DeviceID is in this list and its key matches.

## Authentication on every later connection

After HELLO, the connecting client initiates authentication:

1. The client sends AUTH_CHALLENGE with 16 fresh random bytes.
2. The server looks up the client's HELLO DeviceID in paired.json and closes
    the connection if that device is not paired. It then sends its own fresh
    AUTH_CHALLENGE and an AUTH_RESPONSE signing the client's challenge.
3. The client checks the server ID and stored public key, verifies the server's
    signature, and sends an AUTH_RESPONSE signing the server's challenge.
4. The server verifies the client's signature using the stored public key and
    enters Authenticated state. Invalid signatures or malformed messages close
    the connection.
5. The client sends a PING and requires the matching PONG before Dial reports
    success. This confirms the server accepted its signature, since the server
    only resumes dispatch after successful verification.

Each signature is Ed25519 over
         "WC-AUTH-v1" || challenge || signer DeviceID || verifier DeviceID

Fresh challenges prevent replay. Including both DeviceIDs prevents a signature
from being reused for a different device pair.

## Session states

| State          | Allowed frames                                              |
|----------------|-------------------------------------------------------------|
| Connected      | HELLO only                                                  |
| Greeted        | PING, PONG, ERROR, PAIR_*, AUTH_*                           |
| Authenticated  | everything except HELLO (including NOTIFY, FILE_*, SCREEN)  |

A frame that is not allowed in the current state, and any frame with an
unknown message type, MUST close the connection. States only move forward
one step at a time: Connected, Greeted, Authenticated.

## New message types

| Code | Name          | Payload                          |
|------|---------------|----------------------------------|
| 0x40 | PAIR_REQUEST  | 32-byte commitment               |
| 0x41 | PAIR_RESPONSE | 32-byte pubkey, 16-byte nonce    |
| 0x42 | PAIR_REVEAL   | 32-byte pubkey, 16-byte nonce    |
| 0x43 | PAIR_DECISION | 1 byte (1 accept, 0 reject)      |
| 0x44 | AUTH_CHALLENGE| 16-byte nonce                    |
| 0x45 | AUTH_RESPONSE | 64-byte signature                |

## Implementation plan

1. identity v2: Ed25519 keys, DeviceID derived from the key
2. paired.json store
3. Pairing code (SAS) and AUTH signing helpers, with tests
4. Protocol constants and payload codecs
5. Server state machine: gate features behind Authenticated
6. CLI tool to pair two devices from the terminal

## Test vectors

Inputs (each is a repeated byte):

    pubA   = 32 x 0x0A        pubB   = 32 x 0x0B
    nonceA = 16 x 0xA1        nonceB = 16 x 0xB2

Expected:

    Commitment(pubA, nonceA) =
        c306e36aa18bb73edfeeb5fba85d62230f157214737425a0bdfc5bec53c31ed9
    SASCode(pubA, pubB, nonceA, nonceB)         = 151254
    SASCode(pubB, pubA, nonceA, nonceB)         = 901406   (roles swapped)

Zero-padding case: same inputs, but nonceB = 14 x 0xB2 followed by 0x05 0x87:

    SASCode(pubA, pubB, nonceA, nonceB)         = 000098

AuthMessage layout: "WC-AUTH-v1" (10 bytes) || challenge (16) || signerID (16)
|| verifierID (16) = 58 bytes.