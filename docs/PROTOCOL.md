# WideConnect Protocol v1

Transport: raw TCP, `TCP_NODELAY` enabled, over a Tailscale tunnel.
All multi-byte integers are **big-endian**.

## Frame layout

| Offset | Size | Field    | Description                              |
|--------|------|----------|------------------------------------------|
| 0      | 2    | Magic    | 0x5743 ("WC"), used to detect desync     |
| 2      | 1    | Version  | Protocol version (currently 0x01)        |
| 3      | 1    | Type     | Message type (see below)                 |
| 4      | 4    | Length   | Payload length in bytes (max 16 MiB)     |
| 8      | N    | Payload  | Type-specific body                       |

Header is a fixed 8 bytes.

## Message types

| Code | Name           | Direction          | Purpose                              |
|------|----------------|--------------------|--------------------------------------|
| 0x01 | HELLO          | both               | Handshake: device name, id, caps     |
| 0x02 | PING           | both               | Latency probe (8-byte timestamp)    |
| 0x03 | PONG           | both               | Echo of PING payload                 |
| 0x10 | NOTIFY         | phone→pc            | Notification mirroring              |
| 0x20 | FILE_META      | sender→receiver     | File name, size, hash, transfer ID   |
| 0x21 | FILE_CHUNK     | sender→receiver     | File data at an explicit offset      |
| 0x22 | FILE_DECISION  | receiver→sender     | Accept or reject an offered file     |
| 0x23 | FILE_ACK       | receiver→sender     | Cumulative next expected byte offset|
| 0x24 | FILE_DONE      | receiver→sender     | Transfer verified and committed      |
| 0x25 | FILE_CANCEL    | both               | Cancel an active transfer            |
| 0x30 | SCREEN         | phone→pc            | Screen frame data                   |
| 0x40 | PAIR_REQUEST   | initiator→responder | Pairing commitment (32 bytes)       |
| 0x41 | PAIR_RESPONSE  | responder→initiator | Public key (32) + nonce (16)         |
| 0x42 | PAIR_REVEAL    | initiator→responder | Public key (32) + nonce (16)         |
| 0x43 | PAIR_DECISION  | both               | Accept (1) or reject (0)             |
| 0x44 | AUTH_CHALLENGE | both               | Authentication challenge (16 bytes) |
| 0x45 | AUTH_RESPONSE  | both               | Ed25519 signature (64 bytes)         |
| 0xFF | ERROR          | both               | Error code + message                 |

## Rules

- A receiver MUST close the connection on bad magic or unsupported version.
- A receiver MUST reject frames whose Length exceeds 16 MiB.
- PING/PONG payload is an 8-byte unsigned nanosecond timestamp; PONG echoes it unchanged.
- Pairing and auth payloads have exact fixed lengths. A receiver MUST close the connection on any other length, and on a PAIR_DECISION byte other than 0 or 1.
- Unknown message types and frames not allowed in the current session state MUST close the connection.
- NOTIFY, FILE_*, and SCREEN frames are valid only after authentication succeeds.
- FILE_* messages are accepted only from a device advertising `CapFiles`.

## HELLO payload (0x01)

| Offset | Size | Field        | Description                             |
|--------|------|--------------|-----------------------------------------|
| 0      | 16   | DeviceID     | First 16 bytes of SHA-256(public key)    |
| 16     | 1    | Platform     | 1=Linux, 2=Windows, 3=Android           |
| 17     | 4    | Capabilities | Bitmask: 1=Notify, 2=Files, 4=Screen    |
| 21     | 1    | NameLen      | N, max 64                               |
| 22     | N    | Name         | UTF-8 device name                       |

## Handshake

1. The connecting side sends HELLO immediately after the TCP connection opens.
2. The accepting side validates it and replies with its own HELLO.
3. No other frame type is valid until both HELLOs are exchanged. The session then enters Greeted state.
4. The accepting side MUST close the connection if no valid HELLO arrives within 5 seconds.

## Pairing and authentication payloads

| Type | Payload layout |
|------|----------------|
| PAIR_REQUEST | Commitment (32 bytes) = SHA-256(public key || nonce) |
| PAIR_RESPONSE | Responder public key (32 bytes) || nonce (16 bytes) |
| PAIR_REVEAL | Initiator public key (32 bytes) || nonce (16 bytes) |
| PAIR_DECISION | One byte: 1 = accept, 0 = reject |
| AUTH_CHALLENGE | Random challenge (16 bytes) |
| AUTH_RESPONSE | Ed25519 signature (64 bytes) |

The pairing exchange, short authentication string calculation, and signature
input are specified in [PAIRING.md](PAIRING.md). Pairing and authentication
frames are valid in Greeted state. A successful mutual authentication moves
the connection to Authenticated state; feature frames are rejected before then.

## Session states

| State | Allowed frame classes |
|-------|-----------------------|
| Connected | HELLO only |
| Greeted | PING, PONG, ERROR, PAIR_*, AUTH_* |
| Authenticated | Any known frame except a second HELLO |

## File sharing (MVP)

File sharing is available only in Authenticated state and only when both
devices advertise `CapFiles`. A transfer is one regular file; directory trees,
symbolic links, resume after disconnect, and overwriting existing files are
not part of the initial MVP.

All integer fields below are unsigned and big-endian. `transfer_id` is 16
cryptographically random bytes chosen by the sender and unique among its
active transfers. The sender sends one `FILE_META` at a time for a connection.
The receiver MUST reject a second offer while the first is pending or active.

### FILE_META (0x20), sender to receiver

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 16 | transfer_id | Random transfer identifier |
| 16 | 8 | size | Exact file size in bytes |
| 24 | 32 | sha256 | SHA-256 of the complete file contents |
| 56 | 2 | name_len | UTF-8 filename byte length, 1..255 |
| 58 | N | name | Base filename only; never a path |

The receiver validates the full payload and policy limits before allocating
or creating a destination file. It MUST reject names that are empty, `.` or
`..`, contain `/`, backslash, NUL, or invalid UTF-8. Names are not paths and
MUST NOT select a directory. The receiver chooses the destination directory
from local configuration, displays the peer and filename to the user, and does
not write file content before explicit acceptance. The receiver MUST enforce a
configurable maximum file size and available-space checks; a sender-provided
size is untrusted.

### FILE_DECISION (0x22), receiver to sender

Exactly 17 bytes: `transfer_id` (16) followed by `decision` (1). Decision is
1 to accept or 0 to reject. Any other value is invalid. The receiver sends
this once for each valid offer. Rejection ends the transfer without creating a
file. If the receiver does not decide within the implementation's offer
timeout, the connection is closed and the offer is rejected.

### FILE_CHUNK (0x21), sender to receiver

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 16 | transfer_id | Must match the accepted offer |
| 16 | 8 | offset | Byte offset in the complete file |
| 24 | 1..262144 | data | File bytes |

Chunks MUST be non-empty, no larger than 256 KiB, contiguous, and in order.
The first offset is zero; each next offset equals the end of the preceding
chunk. A receiver MUST reject gaps, overlaps, chunks for another transfer,
and chunks extending beyond the declared size. No chunk is valid before an
accept decision.
For a zero-byte file, the sender sends no FILE_CHUNK; after acceptance the
receiver verifies SHA-256 of the empty content and commits the empty file.

### FILE_ACK (0x23), receiver to sender

Exactly 24 bytes: `transfer_id` (16) followed by `next_offset` (8). It
cumulatively acknowledges all bytes before `next_offset`. The receiver sends
an ACK after each accepted chunk. The sender MUST wait for the matching ACK
before sending the next chunk; `next_offset` must equal the end of that chunk.
This stop-and-wait rule bounds in-flight data and keeps the initial
implementation simple.

### FILE_DONE (0x24), receiver to sender

Exactly 48 bytes: `transfer_id` (16) followed by SHA-256 (32). The receiver
sends FILE_DONE only after exactly `size` bytes have arrived, the computed
SHA-256 matches FILE_META, and the destination has been safely committed. The
sender MUST treat a missing or mismatched FILE_DONE as failure, not success.

The receiver writes to a new temporary file inside the configured destination
directory, never follows a sender-supplied path, and never overwrites an
existing file. On success it atomically publishes the file under a
collision-free name, flushes it to disk, then sends FILE_DONE. On rejection,
cancellation, disconnect, size/hash failure, or write error, it removes the
temporary file.

### FILE_CANCEL (0x25), either direction

Exactly 17 bytes: `transfer_id` (16) followed by `reason` (1). Reason values
are 0 for user cancellation, 1 for policy rejection, and 2 for local I/O
failure. Unknown reasons or a cancellation for a different active transfer
are protocol errors. On cancellation, both sides stop sending data and discard
incomplete transfer state; the connection may remain open if the frame itself
is valid.

The Linux MVP exposes native Go CLI commands (for example, `wcd` for the
daemon and a Go-built `wc` command for sending, receiving, and listing paired
devices). It does not require Python or a script interpreter at runtime. The
same wire layouts are intended for the later Android app.