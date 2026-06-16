# auth-middleware

an access token represents delegated access to a protected resource. RFC 6749 describes OAuth as a framework for giving a client limited access to an HTTP service, either on behalf of a resource owner or on the client’s own behalf

Your backend API only ever receives access tokens, so the middleware validates exactly that: RFC 9068 JWT access tokens, plus the OAuth-family extensions (RFC 6750 Bearer, RFC 9449 DPoP, RFC 8705 mTLS, RFC 9470 step-up).

It actively defends against ID tokens. An ID token is also a signed JWT from the same issuer, so a naive validator would accept one sent to the API ("ID-token replay"). Restricting `acceptedTokenTypes` to `at+jwt` in `AuthConfig.scala` makes that structurally impossible — ID tokens have `typ: JWT`. The default also accepts plain JWT for issuers that don't emit `at+jwt` yet, so tighten it if yours does 

`"OAuth is authorization, not authentication" describes the protocol's purpose between user, client, and authorization server — not what happens at your API`

At the protocol layer: OAuth's job is delegation. The user authorizes a client app to act on their behalf, and the access token is the artifact of that consent. The famous warning "don't use OAuth for authentication" targets a specific historical mistake: client apps treating possession of an access token as proof that a user logged in. Tokens aren't audience-restricted to the client, so a malicious site could replay a token it received and impersonate the user elsewhere. OIDC's ID token — `audience-locked`, with `nonce` — was created precisely to fix that. That warning is about login at the client, and it's real, but it's not about resource servers

`The original warning was aimed squarely at front-end developers and client applications to prevent the "Confused Deputy" problem.`

`aud `(audience) claim matching the client ID and a `nonce` to prevent replay attacks. The ID Token was explicitly built for client-side user authentication

When an API rejects an invalid or missing token, it doesn't return a `403 Forbidden` (which represents an authorization failure). It returns a `401 Unauthorized` accompanied by the `WWW-Authenticate: Bearer` header. The HTTP specification itself categorizes the validation of a bearer token as an authentication event.

`Access tokens are not audience-restricted to the OAuth client; when they are audience-restricted, the intended audience is the resource server/API, not the client application using them.`

- OAuth 2.0 is an authorization framework — it exists to delegate access.
- Within that framework, the resource server authenticates each request by validating the token, then authorizes it via scopes/acr.
- OIDC is for user authentication at the client 

OpenID Connect requires the ID Token’s `aud` claim to contain the OAuth client’s `client_id`, and the client must reject the ID Token if it is not listed as a valid audience. It also defines `nonce` to bind the ID Token to a particular client login request and mitigate replay.


There's also a chronological reason the old warning was phrased so absolutely. In original OAuth 2.0 (RFC 6749, 2012), access tokens were opaque — unspecified format, often just a random string. A client literally couldn't inspect any aud, because there was no structure to read. Audience-restricted and JWT-structured access tokens only got standardized later (Resource Indicators RFC 8707 in 2020, the JWT access-token profile RFC 9068 in 2021).

The ID token's `aud` is set to the `client_id` of the receiving app:
- Alice's ID token from EvilBlog has `aud: "evilblog-client-id"`.
- PhotoApp checks `aud == "photoapp-client-id"` → mismatch → rejected. Replay dead.
So both token types have an `aud` claim — but they point at different kinds of party:

| Token | `aud` points at | Useful for answering |
| --- | --- | --- |
| Access token | the API / resource server | "may this token be used at this API?" |
| ID token | the client app (`client_id`) | "was this login minted for this app?" |


"Mint" just means create/generate/issue — like a mint stamps coins. A value you mint is one your own code produces and emits into the world; a value you receive is one that arrives from someone else and you have to inspect.

- The authorization server mints an `access_token`, a `jti`, an `authorization_code`, a `request_uri`. It chooses the format — say, a 32-byte random value, base64url-encoded, 16–256 chars. Since you generate it, you can guarantee that shape, so the type can be strict (`MintedJti = [A-Za-z0-9._~-]{16,256}`), and you can construct it with a total/compile-time constructor because you'll never feed it garbage.

- The resource server receives an `access_token` in the `Authorization` header, and reads the `jti`, `sub`, and `scope` claims out of it. You didn't make these. Some other authorization server did, and the spec (RFC 7519 ) lets it put almost anything non-blank in a `jti`.

Who authors it	Type strictness	How you build it
TokenJwtId (mint)	your AS generates it	strict (16–256, fixed charset)	total / trusted
ReceivedJwtId (receive)	a peer put it in a token	lenient (non-blank, ≤256)	Either (validate, can reject)

- You mint a route requirement: `Custom(ScopeToken("partner:settlement"))`. You author that string in your own source code, so the curated strict grammar applies and it's validated at compile time — you're the authority, so a violation is your bug to fix now.
- You receive granted scopes: the scope claim from an incoming token, parsed leniently through Inbound.scopes, dropping anything malformed — because a peer authored those and might send something off-spec.

## InMemoryDPoPSingleUseChecker
It's two things: a map and a timer (source).

The replay check — a ConcurrentHashMap<String, Long> from key → insertion timestamp, where the key is i`ssuer + ":" + base64url(SHA-256(jti))`:

```java
public void markAsUsed(DPoPProofUse use) throws AlreadyUsedException {
  String key = use.getIssuer() + ":" + computeSHA256(use.getJWTID());
  if (cachedJTIs.putIfAbsent(key, now) != null)   // atomic check-and-set
    throw new AlreadyUsedException("Detected jti replay");
}
```
`putIfAbsent `is the whole game: if the key was already there, it's a replay → throw. Atomic, so concurrent duplicate proofs can't both slip through.

The eviction — a dedicated `java.util.Timer` (one daemon thread per checker) that wakes every `purgeIntervalSeconds` and does a full `O(n)` scan, deleting entries older than `lifetimeSeconds`:

```java
timer.schedule(new TimerTask {
  run() { for (e <- cachedJTIs) if (e.value < now - lifetime) cachedJTIs.remove(e.key) }
}, purgeInterval, purgeInterval);
```
`shutdown()` just calls `timer.cancel()` — that's the thread you have to remember to stop, which is why I wrapped it in `Resource`.


## Caffeine
Look at the Caffeine version's `markAsUsed`: it's the same `ConcurrentHashMap` + `putIfAbsent` + `the same issuer:SHA-256(jti)` key. It even copies `computeSHA256` verbatim. So Caffeine adds zero to the replay detection or the security property — both are correct and identical.

What changes is the eviction strategy — Nimbus's periodic timer-thread sweep is replaced by Caffeine's per-entry expiry, evicted lazily during normal cache operations (and amortized on the shared `ForkJoinPool`, not a dedicated thread).

- Nimbus runs a dedicated `Timer` thread that, every `purgeIntervalSeconds`, does a full `O(n)` scan of the entire map and removes expired entries. Two costs follow:
  1. A recurring CPU burst proportional to the map size — at high request rates (lots of unique `jti`s inside the retention window), that scan walks every entry on a timer.
  2. Between purges the map holds all entries, including already-expired ones, so memory runs higher than the live set and the larger map makes every lookup touch a bigger structure.
- Caffeine evicts incrementally, amortized `O(1)`, piggybacked on normal cache operations (no dedicated thread, no periodic full sweep). Memory tracks the true live set, and there's no recurring scan spike. It's engineered for high-concurrency hot paths (batched read/write buffers, minimal contention).

Under sustained high load — which is exactly when a payments API gets hammered or when someone floods you with proofs — Nimbus's periodic full-map scan and inter-purge memory growth are the performance hazard, and Caffeine avoids both.

RFC 9068 (the JWT access-token profile) technically lists `sub` as required, and for `client_credentials` it recommends setting `sub` to the client's identifier. So a strictly-9068-compliant AS does still emit a `sub` (= client id).

`jti` is the JWT ID claim (RFC 7519 §4.1.7): a string the issuer puts in a token that uniquely identifies that one token. The issuer assigns it so two tokens essentially never share a `jti` (typically a UUID or random value). Its stated purpose in the spec is to prevent replay 

A DPoP proof is meant to be minted fresh per request to prove possession of the key. Its `jti` is how the resource server enforces "use once":
- The single-use checker (the `InMemoryDPoPSingleUseChecker` / Caffeine thing) records each proof's `jti` (keyed as issuer:SHA-256(jti)). If the same `jti` shows up twice, it's a replay of a captured proof → rejected.
- That's literally `putIfAbsent` on the `jti`: first time wins, second time fails.

## The problem DPoP solves
A normal Bearer token is exactly that — `bearer`: whoever holds the string can use it. Steal it (leaky log, malicious proxy, compromised TLS terminator) and you can replay it anywhere until it expires. DPoP (RFC 9449) makes the token `sender-constrained`: it ties the token to a key the legitimate client holds, so a stolen token alone is useless — you'd also need the client's private key.

## Dpop
The client generates a key pair and keeps the private key. Two phases:
1. *Issuance* — bind the token to the public key. When the client gets the access token, the authorization server stamps a confirmation claim into it: `cnf.jkt = SHA-256 thumbprint` of the client's public key. That's the token saying "I may only be used by whoever can prove they hold the key with this thumbprint." (In our middleware this becomes `AuthContext.confirmation = ConfirmationClaim.DPoP(jkt)`.)

2. *Each request — prove possession*. The client sends two headers:
```sh
Authorization: DPoP <access-token>
DPoP: <proof-jwt>
```

The proof is a small JWT the client mints per request, signed with its private key, that:
- carries the public key in its `jwk` header (so the server can verify the signature and compute the thumbprint), and
- has claims `htm` (HTTP method), `htu` (the request URL), `iat` (issued-at), `ath` (hash of the access token), and `jti` (a unique id for this proof).

## What the resource server verifies (Nimbus verifier)
- The proof's signature checks out against its embedded `jwk` → the sender holds the private key.
- `SHA-256(jwk) == token's cnf.jkt `→ this proof's key is the one the token is bound to. (Forgery defense: an attacker with the stolen token but not the key can't produce a jwk that thumbprints to cnf.jkt.)
- `htm/htu` match this request's method and URL → the proof was made for this endpoint.
- `iat` is fresh (within the max-age window) → not an old proof.
- `ath` == hash(access token) → the proof is bound to this specific token.
- `jti` has not been seen before → the proof is used at most once.


The proof JWT (the value of the DPoP: header) carries:
- `htm` = HTTP method → the server compares it against the request's actual method (GET, POST, …).
- `htu` = HTTP target URI (the endpoint/URL) → the server compares it against the request's actual URL (`scheme + host + path`; query and fragment are stripped first).
Both must match, or the proof is rejected (`invalid_dpop_proof`).

Why both claims exist: `they bind the proof to one specific operation`. A proof captured for `GET /accounts` can't be replayed as `POST /payments` (wrong `htm` and `htu`), and a proof for `https://api.example.com/...` can't be aimed at a different host. Combined with `ath` (binds to the specific token) and `jti` (one-shot), the proof is pinned to exactly: this method, this URL, this token, once, within the freshness window

`OAuth 2.0 is a framework for delegated authorization, and the access token is the artifact that delegation produces`

The access token is just how that grant is represented and carried
`the token carries authorization, but verifying the token is genuine is authentication — and you can't act on what a credential permits until you've confirmed the credential is real.`

At the resource server, the first question is: is this token genuine? Real signature from my trusted AS, intact, unexpired, for my audience, (with DPoP/mTLS) presented by the party it's bound to. Verifying that a presented credential is authentic is authentication — the same way checking a password or a client certificate is.

`Checking that the grant is real is authentication; acting on what it permits is authorization. Authorization presupposes authentication `

In our middleware, every DPoP outcome is an authentication outcome:
- missing / invalid / replayed proof → `invalid_dpop_proof` → 401
binding violation (bound token presented as Bearer, thumbprint mismatch) → `invalid_token` → 401
- "must be sender-constrained" → `invalid_token` → 401
- None of them produce 403 `insufficient_scope`. Authorization failures are 403; DPoP failures are 401.


authentication" = proving genuineness (of the client, the request, the flow, the token's possessor, or the user), and "authorization" = defining, scoping, delegating, or revoking what access is granted. Also note where each acts — many strengthen authentication at the authorization server / flow layer, a few at the resource server.

## Strengthen AUTHENTICATION

| Extension | RFC | What it strengthens / where |
| --- | --- | --- |
| PKCE | 7636 | Binds code redemption to the client that started the flow (anti code-interception) — flow/request auth at the AS |
| mTLS | 8705 | Two parts: client auth to the AS via TLS cert and certificate-bound (PoP) access tokens — client + request auth |
| DPoP | 9449 | Application-layer proof-of-possession; sender-constrains the token — request auth at the RS |
| cnf confirmation | 7800 | The PoP-binding representation (`jkt`, `x5t#S256`) underpinning DPoP/mTLS — request auth |
| Assertion framework / JWT / SAML client auth | 7521 / 7523 / 7522 | `private_key_jwt` etc. — client authenticates to the AS with a signed assertion — client auth |
| PAR (Pushed Authorization Requests) | 9126 | Auth request pushed server-side, tied to an authenticated client, untamperable in the front channel — request authenticity |
| JAR (JWT-Secured Authorization Request) | 9101 | Signs/encrypts the auth request — request authenticity/integrity |
| Issuer Identification | 9207 | `iss` in the authz response; defeats AS mix-up — response authenticity |
| Step-up Authentication Challenge | 9470 | Demands stronger/fresher user auth (`acr`/`max_age`) — user-auth strength |
| JWT Profile for Access Tokens | 9068 | Structured tokens the RS can authenticate locally (signature/`iss`/`aud`/`exp`) — enables request/token auth |
| HTTP Message Signatures | 9421 | Signs HTTP messages (used by FAPI) — message/request authenticity |
| Native Apps BCP | 8252 | Secure the flow (system browser + PKCE) — flow auth |
| (OIDC Core / ID Token — layered on OAuth) | — | The user-authentication layer OAuth itself omits — user auth |

## Strengthen AUTHORIZATION

| Extension | RFC | What it strengthens / where |
| --- | --- | --- |
| Rich Authorization Requests (RAR) | 9396 | `authorization_details` — fine-grained, structured authz beyond scopes — grant precision |
| Resource Indicators | 8707 | `resource` param → audience-restricted tokens — scopes where a token may be used |
| Token Exchange | 8693 | Delegation / impersonation (act-as / on-behalf-of) — delegated authz |
| Token Revocation | 7009 | Client revokes a grant — authz lifecycle (un-grant) |
| Device Authorization Grant | 8628 | A flow to obtain authorization on input-limited devices — authorization grant |

## Hybrid (do both)

| Extension | RFC | Note |
| --- | --- | --- |
| Token Introspection | 7662 | RS asks the AS "is this token active/genuine?" (authentication of the token) and gets its scopes (authorization) |
| Security BCP | 9700 | Cross-cutting hardening — mandates PKCE, sender-constraining, no implicit, etc. (both sides) |
| FAPI 1.0 / 2.0 profiles | — | Combine many of the above into a high-assurance profile (both) |

## Supporting / operational (neither directly)

| Extension | RFC | Note |
| --- | --- | --- |
| AS Metadata / Discovery | 8414 | How clients discover endpoints/capabilities |
| Dynamic Client Registration / Management | 7591 / 7592 | Establishes client identity (an authn foundation) but is operational |
| Bearer Token Usage | 6750 | The baseline request authentication (the weak, stealable form that DPoP/mTLS strengthen) |

The authentication-strengthening extensions cluster around three proof-of-possession ideas — proving the client is real (mTLS/JWT client auth), proving the request/flow is real and untampered (PKCE, PAR, JAR, issuer-id), and proving the token's holder is the bound party (DPoP, mTLS binding, cnf). The authorization-strengthening ones cluster around shaping the grant — making it more precise (RAR), narrower in audience (Resource Indicators), delegable (Token Exchange), or revocable (Revocation). Step-up and sender-constraint policy sit on the authentication side even though they gate access, because what they check is authentication strength, not a permission 

A protocol nails down the exact bytes on the wire so two independent implementations interoperate out of the box (think TLS, HTTP). OAuth 2.0 doesn't do that — it gives you a kit of parts and lets you assemble (and extend) a concrete system.

Here's what's left open, which is exactly what makes it a framework and not a protocol:
- Multiple grant types, not one handshake. Authorization code, client credentials, refresh, device, implicit (now deprecated) — you pick the flow for your situation. And it defines extension grants (the urn:ietf:params:oauth:grant-type:* mechanism), so brand-new flows like token exchange and CIBA slot in without changing the core. A protocol would specify one exchange.
- The token format is unspecified. RFC 6749 never says what an access token is — opaque string or JWT, your choice. That's why RFC 9068 (the JWT profile) exists later to fill it in. A protocol would mandate the format.
- Major details are deferred. How the resource server validates a token, which client-authentication method is used, token lifetimes, what scopes mean — the core mostly leaves these to you, to extensions, or to profiles.
- Extension points and registries everywhere. New parameters, new endpoints, new token types, new grant types — all have defined places to plug in, backed by IANA registries. The entire list of extensions(PKCE, DPoP, PAR, RAR, mTLS, …) exists because the core was built as a framework with these seams.

The practical consequence: two OAuth deployments can look quite different on the wire and both be valid OAuth — `which means OAuth alone doesn't guarantee interoperability or security`. That gap is exactly why profiles (FAPI 1.0/2.0), OpenID Connect, BCPs (RFC 9700), and OAuth 2.1 exist — they re-tighten the framework into something interoperable and secure for a given context. FAPI, for instance, says "for financial-grade, you must use PKCE + PAR + sender-constrained tokens + these algorithms" — turning the open framework into a pinned-down profile.

the framework design is what lets OAuth serve everything from a CLI script to a banking API — enormous flexibility — but that same underspecification is what produced years of insecure implementations, which the profiles and BCPs now exist to correct.

A protocol is a strict, unambiguous set of rules governing how two systems communicate. It defines the exact bits, bytes, headers, and sequence of operations. There is no room for interpretation. If you deviate from the protocol, the connection fails.

A profile takes a broad, flexible framework (or standard) and aggressively constraints it for a specific industry or use case. Frameworks offer too many choices; a profile makes those choices for you to guarantee security or interoperability in a specific domain.

`without a server nonce, proofs can be pre-generated — their freshness is bounded only by iat/max-age plus single-use. A server nonce ties each proof to a value the server minted just in time, so an attacker can't prepare proofs ahead of capture, and it gives the server tight control over freshness — especially valuable when you can't guarantee cross-node single-use replay protection `

Our `AuthMiddleware` currently produces either an authenticated request or a failure response — it doesn't shape successful responses. Issuing/rotating `DPoP-Nonce` means adding headers to outgoing responses (at minimum the `use_dpop_nonce` 401; ideally rotating on success too), which is a slightly different integration point than pure authentication.

1. RFC 9068 requires both sub and client_id, and says of sub:
In case the access token is obtained via a grant where a resource owner is not involved, such as the client credentials grant, the value of sub SHOULD correspond to an identifier the authorization server uses to indicate the client application.

2. presence of user-authentication claims (§2.2.1)
RFC 9068 §2.2.1 ("Authentication Information Claims") defines `auth_time`, `acr`, and `amr` as describing the resource owner's authentication event. They're only meaningful when a user authenticated, and are not included for grants without user authentication (client credentials). So:
- `auth_time` / `acr` / `amr` present ⇒ a user authenticated.
all absent ⇒ likely M2M