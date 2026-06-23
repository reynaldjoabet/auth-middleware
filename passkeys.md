## Passkeys
WebAuthn (Web Authentication API) is a W3C standard that defines an API for creating and using strong, attested, public-key-based credentials for web applications. It is a core component of the broader FIDO2 framework

Instead of relying on shared secrets (like passwords or OTPs), WebAuthn relies on asymmetric cryptography. When operating within an identity architecture, it typically functions at the Authorization Server level, authenticating the user before issuing an OpenID Connect ID token or an OAuth 2.0 access token.

Here is the mechanical breakdown of how it works:
- `Registration`: The Relying Party (RP) requests the creation of a credential. The user's device (the Authenticator) generates an asymmetric key pair. The private key is securely stored on the authenticator, and the public key is sent to the RP to be associated with the user's account.
- `Authentication`: The RP generates a cryptographically secure random challenge. The Authenticator prompts the user for local verification (e.g., biometric scan, PIN). Once verified, the Authenticator uses the private key to sign the challenge and returns the signature to the RP. The RP verifies the signature using the stored public key.

If you are familiar with Demonstrating Proof-of-Possession (DPoP) for API security, WebAuthn operates on a very similar philosophy: the server issues a challenge, and the client proves possession of a private key by signing that challenge, eliminating the risk of credential interception or replay attacks.

Early WebAuthn (Security Keys): Initially, WebAuthn was heavily associated with physical hardware tokens (like YubiKeys). These generated non-discoverable credentials. The key pair was bound to that specific piece of hardware. If you lost the hardware, you lost the credential.

The Passkey Evolution: The FIDO Alliance, Apple, Google, and Microsoft collaborated to create "Passkeys." A Passkey is a WebAuthn credential where the private key is securely synced across a user's devices via a cloud provider's ecosystem (e.g., Apple iCloud Keychain, Google Password Manager).

WebAuthn is the underlying technical standard and JavaScript API (`navigator.credentials.create()`, `navigator.credentials.get()`) that developers implement.

Passkeys are the actual cryptographic entities (the key pairs) created by WebAuthn, specifically designed to be synced across devices to solve the account recovery and hardware-loss friction of early FIDO implementations.

You use the WebAuthn API to provision and invoke Passkeys.

The Relying Party (RP) is the website, application, or service that you are trying to log into.

A website does not receive your fingerprint, face scan, PIN, or private key. Instead, the browser asks an authenticator to prove possession of a private key. The authenticator could be:
```sh
Platform authenticator:
  Touch ID, Face ID, Windows Hello, Android screen lock

Roaming authenticator:
  YubiKey, hardware security key, phone used cross-device
```
Passkeys are often discoverable credentials, meaning the authenticator can help identify the user account without the site first asking for a username. They may also be synced across a user’s devices by a platform or password manager, although some credentials can remain device-bound, such as those on a hardware security key

## Why passkeys are phishing-resistant
- With passwords, a fake site can trick the user into typing the password.
- With WebAuthn/passkeys, the credential is scoped to the real relying party, such as: `bank.example`
A fake site such as: `bank-example-login.attacker.com`
cannot get a valid signature for `bank.example`. The authenticator signs challenges only for the correct relying party context. That origin/RP binding is a major reason passkeys are considered phishing-resistant.

### Platform Authenticators (Built-in)
These are authenticators built directly into the device you are currently using. They rely on the hardware's secure enclave (a dedicated, isolated chip) to protect the private keys.
- Apple Devices: Touch ID or Face ID on a MacBook or iPhone.
- Windows: Windows Hello (using facial recognition, fingerprint, or PIN backed by the device's TPM chip).
- Android: The Android biometric prompt (fingerprint or face scan).

### Roaming Authenticators (Cross-device)
These are external tools that can hold passkeys and be used across different devices.
- Hardware Security Keys: Physical devices like a YubiKey or Google Titan key. You plug them into a USB port or tap them via NFC.
- Third-Party Password Managers: Applications like 1Password, Bitwarden, or Dashlane. These act as software authenticators, storing your passkeys in their encrypted vaults and syncing them across any operating system you use.

`The authenticator is the component that creates and uses the cryptographic key.`

The authenticator can create many credentials:
Your phone authenticator:
- passkey for github.com
- passkey for google.com
- passkey for your-bank.com
- passkey for internal-company-app.com

### Passkey
A passkey is the user-friendly name for a FIDO/WebAuthn authentication credential. FIDO describes a passkey as a FIDO authentication credential tied to a user’s account on a website or app.

That passkey contains or is associated with:
- private key       -> kept secret by authenticator/passkey provider
- public key        -> given to example-bank.com
- credential id     -> identifier for this passkey
- relying party id  -> example-bank.com
- user handle       -> Alice's account id at that site
- metadata          -> algorithm, flags, backup/sync info, etc.

Software Authenticators (Apple Keychain, Google Password Manager, Bitwarden, 1Password): These can hold practically unlimited passkeys. They function just like traditional password managers in this regard.

Hardware Authenticators (YubiKeys, Titan Keys): Because they have physical storage constraints on their secure chips, they do have limits for discoverable credentials (passkeys). Depending on the model and the manufacturer, a single physical security key can typically hold anywhere from 25 to 100 passkeys.


