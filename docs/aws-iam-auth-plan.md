# AWS IAM Database Authentication for provider-sql

## Context

The Crossplane provider-sql currently only supports static username/password authentication via Kubernetes Secrets. We want to add AWS IAM database authentication for Aurora/RDS, allowing the provider to connect using Pod Identity or IRSA instead of static credentials.

**Motivation:** Aurora supports IAM database authentication where a short-lived token (15 min) replaces the password. Combined with EKS Pod Identity or IRSA, this eliminates static database credentials entirely.

**Related upstream work:**
- PR #166: Azure AD auth for MSSQL (open/stale, uses secret-key detection approach, never formally reviewed)
- Issue #165: Azure AD auth for MSSQL
- Issue #196: Entra ID for Azure PostgreSQL (maintainer chlunde asked about scope separation)
- Issue #347: **this work** — AWS IAM DB auth (authored by michielvha). Maintainer `kkendzia` responded positively ("I like this and we would appreciate a contribution") with one caveat: enabling IAM auth requires an initial password connection to modify the DB (`GRANT rds_iam`), so password access is a bootstrapping prerequisite.
- Issue #393: pluggable HTTP credential-helper source for the **master** user (authored by giepa). Explicitly complementary to #347, not competing — see Issue Landscape below.
- Issue #106 (CLOSED/completed): earlier "Support RDS IAM authentication" request. Thread shows IAM-authed *user creation* is already achievable via the existing `Role` + `Grant` resources (tenitski's working example), and the `rds_iam` underscore-naming snag was resolved by external-name support (#261). The **provider-authentication** half — connecting via an IAM token — was never delivered. That gap is what this PR fills.

**Scope:** This PR covers **provider authentication only** — how the provider connects to Aurora. Creating IAM-authenticated database users (`GRANT rds_iam TO myuser` for PG, `IDENTIFIED WITH AWSAuthenticationPlugin` for MySQL) is a separate follow-up PR, per maintainer preference on #196, and is **already largely possible today** via existing `Role`/`Grant` resources (see #106).

---

## Issue Landscape & Maintainer Signal

**Where this stands (as of analysis):**

- **#347 is endorsed.** Maintainer `kkendzia` invited the contribution. The only design note is the bootstrapping prerequisite (below), which is an operator/runbook concern, not a provider code path.
- **#347 and #393 are complementary.** #393 (giepa) adds an HTTP credential-helper for the *master* user; #347 issues IAM tokens for an already-IAM-configured provisioning user. A `ProviderConfig` picks whichever fits its connecting user. giepa explicitly offered to coordinate naming/structure — worth a courtesy sync, but the two features touch the same extension point (`ProviderCredentials.Source`) without colliding.
- **#106 backs the scoping.** User-creation is already solved via existing resources; provider-auth is the missing piece. This is the strongest justification for the "provider auth only" scope when reviewers ask "why not also create the users?"

**Critical prerequisite — do NOT IAM-enable the RDS master user.** Per giepa's analysis on #393:
- Postgres: `GRANT rds_iam` to a role **permanently disables password auth** for it. Doing this to the master breaks AWS-managed rotation, snapshot restore, and break-glass.
- MySQL: `AWSAuthenticationPlugin` is fixed at `CREATE USER` time — no conversion path for the master.

Therefore the provider must connect as a **dedicated provisioning role** (e.g. `crossplane_admin`) that is granted `rds_iam` **plus** the privileges needed to manage databases/roles/grants — never as the RDS master. This is a one-time operator setup (requires a password connection to create+grant the role), and must be documented prominently in the examples and README. The provider itself never performs this bootstrap.

---

## Decisions

- **Enum value:** `AWSIAMAuth` (database type is implicit from API group)
- **PR scope:** Both MySQL and PostgreSQL in one PR
- **Feature scope:** Provider authentication only (not IAM user/role creation)

## Contribution Process

### PR Requirements
- All commits signed off: `git commit -s` (DCO requirement)
- Conventional commit prefix: `feat: add AWS IAM database authentication`
- Run `make reviewable` before pushing
- Fill out PR template (description, Fixes #, checklist, test plan)
- Don't force-push to address review feedback — add subsequent commits

---

## Technical Design

### Approach: New CredentialsSource Enum + Token Injection

**Why not the PR #166 "magic key" approach:** PR #166 detects Azure AD from a `fedauth` key in the secret data. This has never been reviewed or endorsed by maintainers. A new enum value on `Source` is more explicit, validates at CRD admission time, and is the natural extension point the API was designed for. The existing reconciler code even has a comment acknowledging only one source exists today:

```go
// We don't need to check the credentials source because we currently only
// support one source (MySQLConnectionSecret), which is required and
// enforced by the ProviderConfig schema.
```
(pkg/controller/cluster/mysql/database/reconciler.go:115-117)

### How AWS IAM DB Auth Works
1. Connection secret still provides `endpoint`, `port`, `username` (no password)
2. At Connect() time, call `auth.BuildAuthToken()` from AWS SDK v2
3. The returned token is used AS the password in the DSN
4. SSL/TLS is required and auto-enforced
5. AWS SDK discovers credentials from environment (Pod Identity, IRSA, instance metadata)

### Key Architectural Decision: Token Injection at Connect()

The `newDB` function signatures remain **unchanged**:
- MySQL: `New(creds map[string][]byte, tls *string, binlog *bool) xsql.DB`
- PostgreSQL: `New(creds map[string][]byte, database, sslmode string) xsql.DB`

Instead, **before** calling `newDB`, the Connect() method injects the generated IAM token into `creds[password]`. The client layer never knows about IAM — it just sees a password. This minimizes blast radius.

> **Injection point moved (#362 SecretKeyMapping merged).** The cluster reconcilers no longer pass `s.Data` straight to `newDB`. They now remap first:
> ```go
> secretData := xsql.RemapCredentialKeys(s.Data, pc.Spec.Credentials.SecretKeyMapping.ToMap())
> return &external{db: c.newDB(secretData, tlsName, ...)}, nil
> ```
> Token injection must therefore run **on `secretData` after the remap**, not on `s.Data`. Verified present in e.g. `pkg/controller/cluster/mysql/database/reconciler.go:133`. The namespaced path is unaffected (injection happens centrally in `provider.go` — see step 4).

For namespaced controllers, token injection happens in the centralized `provider.GetProviderConfig()` helper, meaning **zero changes** to the 9 individual namespaced reconciler files.

---

## Implementation Steps

### 1. New package: `pkg/clients/awsiam/awsiam.go`

Create a shared token generation package:

```go
package awsiam

// ResolveRegion returns region from: spec field > secret "region" key > empty (SDK default)
func ResolveRegion(specRegion *string, creds map[string][]byte) string

// InjectToken generates an IAM auth token and writes it as the password in creds.
// Reads endpoint, port, username from creds. Returns error if any are missing.
func InjectToken(ctx context.Context, creds map[string][]byte, region string) error
```

New dependency: `github.com/aws/aws-sdk-go-v2/config` + `github.com/aws/aws-sdk-go-v2/feature/rds/auth`

Unit test file: `pkg/clients/awsiam/awsiam_test.go`

### 2. API type changes (6 files)

Add new credential source constant `AWSIAMAuth` and optional `Region *string` field to each ProviderCredentials struct.

**Cluster-scoped MySQL** — `apis/cluster/mysql/v1alpha1/provider_types.go`:
- Add: `CredentialsSourceAWSIAMAuth xpv1.CredentialsSource = "AWSIAMAuth"`
- Change enum: `+kubebuilder:validation:Enum=MySQLConnectionSecret;AWSIAMAuth`
- Add to `ProviderCredentials`: `Region *string` with json tag `"region,omitempty"`

**Cluster-scoped PostgreSQL** — `apis/cluster/postgresql/v1alpha1/provider_types.go`:
- Add: `CredentialsSourceAWSIAMAuth xpv1.CredentialsSource = "AWSIAMAuth"`
- Change enum: `+kubebuilder:validation:Enum=PostgreSQLConnectionSecret;AWSIAMAuth`
- Add to `ProviderCredentials`: `Region *string` with json tag `"region,omitempty"`

**Namespaced MySQL** — `apis/namespaced/mysql/v1alpha1/provider_types.go`:
- Add: `CredentialsSourceAWSIAMAuth MySQLConnectionSecretSource = "AWSIAMAuth"`
- Change enum: `+kubebuilder:validation:Enum=MySQLConnectionSecret;AWSIAMAuth`
- Add `Region *string` to `ProviderCredentials`

**Namespaced MySQL ClusterProviderConfig** — `apis/namespaced/mysql/v1alpha1/cluster_provider_types.go`:
- Same enum + Region changes to `ClusterProviderCredentials`

**Namespaced PostgreSQL** — `apis/namespaced/postgresql/v1alpha1/provider_types.go`:
- Add: `CredentialsSourceAWSIAMAuth PostgreSQLConnectionSource = "AWSIAMAuth"`
- Change enum: `+kubebuilder:validation:Enum=PostgreSQLConnectionSecret;AWSIAMAuth`
- Add `Region *string` to `ProviderCredentials`

**Namespaced PostgreSQL ClusterProviderConfig** — `apis/namespaced/postgresql/v1alpha1/cluster_provider_types.go`:
- Same enum + Region changes to `ClusterProviderCredentials`

### 3. Cluster-scoped reconciler Connect() changes (9 files)

In each cluster reconciler's `Connect()` method, after fetching the secret and before calling `newDB`, add IAM token injection:

**MySQL reconcilers** (3 files):
- `pkg/controller/cluster/mysql/database/reconciler.go`
- `pkg/controller/cluster/mysql/user/reconciler.go`
- `pkg/controller/cluster/mysql/grant/reconciler.go`

Pattern (note: operate on `secretData` **after** `RemapCredentialKeys`, before `newDB`):
```go
secretData := xsql.RemapCredentialKeys(s.Data, pc.Spec.Credentials.SecretKeyMapping.ToMap())
if pc.Spec.Credentials.Source == v1alpha1.CredentialsSourceAWSIAMAuth {
    region := awsiam.ResolveRegion(pc.Spec.Credentials.Region, secretData)
    if err := awsiam.InjectToken(ctx, secretData, region); err != nil {
        return nil, errors.Wrap(err, errGenerateIAMToken)
    }
    forceTLS := "true"
    tlsName = &forceTLS  // Force TLS for IAM auth
}
return &external{db: c.newDB(secretData, tlsName, mg.Spec.ForProvider.BinLog)}, nil
```

**PostgreSQL reconcilers** (6 files):
- `pkg/controller/cluster/postgresql/database/reconciler.go`
- `pkg/controller/cluster/postgresql/role/reconciler.go`
- `pkg/controller/cluster/postgresql/grant/reconciler.go`
- `pkg/controller/cluster/postgresql/extension/reconciler.go`
- `pkg/controller/cluster/postgresql/schema/reconciler.go`
- `pkg/controller/cluster/postgresql/default_privileges/reconciler.go`

Pattern (operate on `secretData` after `RemapCredentialKeys`):
```go
secretData := xsql.RemapCredentialKeys(s.Data, pc.Spec.Credentials.SecretKeyMapping.ToMap())
if pc.Spec.Credentials.Source == v1alpha1.CredentialsSourceAWSIAMAuth {
    region := awsiam.ResolveRegion(pc.Spec.Credentials.Region, secretData)
    if err := awsiam.InjectToken(ctx, secretData, region); err != nil {
        return nil, errors.Wrap(err, errGenerateIAMToken)
    }
    sslMode := "require"
    pc.Spec.SSLMode = &sslMode  // Force SSL for IAM auth
}
```

### 4. Namespaced provider helper changes (2 files)

**`pkg/controller/namespaced/mysql/provider/provider.go`**:
- Add `CredentialsSource` field to `ProviderInfo` struct
- In both ProviderConfig and ClusterProviderConfig branches, capture the source
- After fetching the secret, if source is `AWSIAMAuth`:
  - Call `awsiam.InjectToken()` on the secret data
  - Force TLS to `"true"`

**`pkg/controller/namespaced/postgresql/provider/provider.go`**:
- Add `CredentialsSource` field to `ProviderInfo` struct
- Same injection pattern
- Force SSLMode to `"require"`

This means **zero changes** to the 9 namespaced reconciler files — they just receive creds with the token already injected.

### 5. Dependencies (`go.mod`)

```
go get github.com/aws/aws-sdk-go-v2/config@latest
go get github.com/aws/aws-sdk-go-v2/feature/rds/auth@latest
go mod tidy
```

### 6. Code generation

```
make generate  # regenerates deepcopy and CRDs
```

### 7. Example manifests (4 new files)

- `examples/cluster/mysql/config_iam.yaml`
- `examples/cluster/postgresql/config_iam.yaml`
- `examples/namespaced/mysql/config_iam.yaml`
- `examples/namespaced/postgresql/config_iam.yaml`

Example (cluster PostgreSQL):
```yaml
apiVersion: postgresql.sql.crossplane.io/v1alpha1
kind: ProviderConfig
metadata:
  name: aurora-iam
spec:
  credentials:
    source: AWSIAMAuth
    connectionSecretRef:
      namespace: crossplane-system
      name: aurora-conn  # endpoint, port, username (no password needed)
    # region: us-east-1  # optional, defaults to AWS SDK credential chain
  sslMode: require  # enforced automatically for IAM auth
```

### 8. Unit tests

- `pkg/clients/awsiam/awsiam_test.go`:
  - `TestResolveRegion` — spec > secret > empty fallback
  - `TestInjectToken` — mock AWS SDK, verify password is injected
  - `TestInjectToken_MissingKeys` — error on missing endpoint/port/username

---

## File Change Summary

| Category | Files | Nature |
|----------|-------|--------|
| **New** | `pkg/clients/awsiam/awsiam.go` | Token generation + region resolution |
| **New** | `pkg/clients/awsiam/awsiam_test.go` | Unit tests |
| **API types** | 6 files in `apis/` | Add enum value + Region field |
| **Cluster reconcilers** | 9 files in `pkg/controller/cluster/` | Token injection in Connect() |
| **Namespaced providers** | 2 files (`provider.go`) | Token injection in GetProviderConfig() |
| **Namespaced reconcilers** | 0 files (!) | Changes absorbed by provider.go |
| **Dependencies** | `go.mod`, `go.sum` | AWS SDK v2 |
| **Generated** | deepcopy + CRD YAMLs | `make generate` |
| **Examples** | 4 new YAML files | IAM auth configs |

**Total hand-written file changes: ~17 files**

---

## Verification

1. `make reviewable` — must pass (lint, generate, test)
2. Unit tests for `pkg/clients/awsiam/` package
3. Manual testing with an actual Aurora cluster:
   - Enable IAM auth on the Aurora cluster
   - **Bootstrap (one-time, password connection):** create a dedicated provisioning role (NOT the master), grant it `rds_iam` (PG) / create with `AWSAuthenticationPlugin` (MySQL), plus the privileges needed to manage databases/roles/grants
   - Map an IAM role/policy (`rds-db:connect`) to that DB user
   - Configure EKS Pod Identity / IRSA on the provider's ServiceAccount
   - Create a connection Secret with `endpoint`, `port`, `username` (the provisioning role) — no password
   - Create ProviderConfig with `source: AWSIAMAuth`
   - Verify provider can create/manage databases, and that token regeneration works across reconciles (>15 min)

---

## Commit Strategy

Recommend logical commits (not one giant commit):
1. `feat: add AWS IAM auth client package` — new `pkg/clients/awsiam/` + tests
2. `feat: add AWSIAMAuth credential source to API types` — all 6 API files + generated code
3. `feat: add IAM token injection to cluster reconcilers` — 9 cluster reconciler files
4. `feat: add IAM token injection to namespaced providers` — 2 provider.go files
5. `docs: add IAM auth example manifests` — 4 example YAML files

Each commit signed off (`git commit -s`).
