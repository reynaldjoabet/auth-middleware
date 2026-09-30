
### example endpoint
```http
GET /api/payroll/employees
```
```ssh
Policy:
Requires:
    PayrollAdmin
OR
    payroll.read
```
The authorization middleware could effectively perform:
```sh
if token.invalid:
    return 401
if token lacks required role/scope:
    return 403
continue request
```
The distinction is important:

### *401 Unauthorized*

The caller does not present a valid authentication credential.

Examples:
- Expired token.
- Invalid signature.
- Invalid issuer.
- Invalid audience.
- Token explicitly invalidated.

### *403 Forbidden*

The token is valid, but the caller lacks the required authorization.

Example:
*Valid token + No PayrollAdmin role + No payroll.read scope = 403*


## Consumer Invalidation Workflow

Each token-consuming service subscribes to the invalidation event stream.
```sh
                       STS
                        |
                        |
                Token invalidated
                        |
                        v
                      Kafka
                        |
           +------------+------------+
           |            |            |
           v            v            v
        API A         API B        API C
           |            |            |
           v            v            v
      Local revoke  Local revoke  Local revoke
        store          store         store
```
When a consumer receives:
```sh
TokenInvalidated(jti=ABC)   
```
it adds the token identifier to its local invalidation cache/store.

Subsequent requests containing that token are rejected.

### Role Changes

Adding role claims introduces an important lifecycle question.

Example:
```sh
10:00
User receives:
    roles = [Manager]
10:05
Manager role removed.
10:06
User presents existing token.
```
The token still contains:
```sh
"roles": ["Manager"]
```
Therefore, role claims alone do not provide immediate role revocation.

There are two possible approaches.
Option A: Invalidate tokens when roles change

When a security-relevant authorization change occurs:
```sh
Role change
   |
   v
Invalidate affected tokens
   |
   v
Publish Kafka event
   |
   v
Consumers revoke token
```
The user then obtains a new token containing the updated roles.
