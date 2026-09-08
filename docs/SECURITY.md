# Pair security

Pair protects note traffic with TLS 1.3 from rustls using ring cryptography. It
does not use public certificate authorities because a LAN host normally has no
stable DNS identity.

## First pairing

1. The client discovers the host or connects to a manually entered address.
2. A provisional TLS session verifies the certificate's handshake signature
   but has no trusted certificate pin yet. The interface labels this session
   **Unverified**.
3. The provisional session accepts only bounded pairing-control messages. The
   host does not release the note, ownership state, or a reconnect token.
4. Both devices display six code words derived from 48 bits of the SHA-256 host
   certificate fingerprint. Users must compare the phrases through direct
   visual inspection and confirm on both devices.
5. The host sends a temporary, OS-random 256-bit token. The client atomically
   saves that token and the exact certificate fingerprint, then acknowledges
   the save. Only then does the host save or replace that peer and complete
   pairing. An interrupted attempt before the acknowledgement consumes no slot.
6. Both sides close the provisional session. The normal connection succeeds
   only after exact certificate pinning, TLS
   handshake-signature verification, and constant-time token authentication.

A machine-in-the-middle that terminates TLS presents a different certificate
and therefore a different phrase. Pairing is secure only when the user actually
checks that both phrases match. Discovery names and IP addresses are convenient
labels, not trust anchors.

## Later connections

The client pins the saved SHA-256 certificate fingerprint. A changed
certificate is rejected without a bypass. A host stores up to eight independent
peer tokens and admits only one peer at a time. Removing a paired device revokes
only its token. **Reset Identity** replaces the host certificate and private key
and revokes every paired peer.

## Stored data

Pair stores a random device ID, display name, host certificate and private key,
trusted peer metadata, pinned fingerprint, reconnect token, and last address.
It writes a versioned, bounded settings file through atomic replacement. On
Unix, Pair requests mode `0700` for its settings directory and `0600` for the
file. On Windows it relies on the current user's profile ACL.

Notes and recovery drafts are never written by Pair. They remain in process
memory and disappear when Pair closes. Pair has no telemetry, text logging,
clipboard monitoring, automatic execution, or cloud component.

## Limits

- Pair assumes both screens are visible or the phrase is compared through an
  authenticated human channel.
- Device compromise exposes that device's saved credentials and visible note.
- TLS does not hide connection metadata such as IP addresses and timing.
- Pair is intended for local networks and should not be exposed directly to the
  internet.
