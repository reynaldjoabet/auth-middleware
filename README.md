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
