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

## Verification Findings (empirical)

These were verified against the actual codebase and the real AWS SDK, not assumed. Sources are listed in [References](#references).

**Code-path audit (against current `master`):**
- ✅ **Namespaced centralization is real.** All 3 MySQL + 6 PostgreSQL namespaced reconcilers obtain credentials *exclusively* via `provider.GetProviderConfig()` ([`pkg/controller/namespaced/{mysql,postgresql}/provider/provider.go`]). Injecting there genuinely requires **zero** reconciler edits.
- ✅ **Cluster path** builds `secretData := xsql.RemapCredentialKeys(s.Data, …)` then calls `newDB` on the next line — injection slots cleanly between (all 9 reconcilers, identical shape).
- ✅ **Password injection point** confirmed: both clients read `creds[xpv1.ResourceCredentialsSecretPasswordKey]`; endpoint/port/user keys (`…SecretEndpointKey`, `…SecretPortKey`, `…SecretUserKey`) are present in the creds map.

**AWS SDK `BuildAuthToken` behavior (verified with a local Go probe using real SSO credentials, no DB):**
- Signature: `auth.BuildAuthToken(ctx, endpoint, region, dbUser string, creds aws.CredentialsProvider, optFns ...) (string, error)`. Pinned versions tested: `config v1.32.25`, `feature/rds/auth v1.6.29`.
- ✅ **Endpoint must be `host:port`** — passing a bare host errors: *"the provided endpoint is missing a port, or the provided port is invalid"*. So `InjectToken` must assemble `endpoint + ":" + port` from the creds map.
- ⚠️ **Empty region does NOT error at generation time** — it silently produces a malformed token that the DB rejects later. **Correction to earlier assumption:** the SDK will not guard this for us; our code must resolve a non-empty region and error if it can't.
- ✅ `config.LoadDefaultConfig(ctx)` resolved `cfg.Region` from the environment (`AWS_REGION`/IMDS) — a valid final fallback for region resolution.
- ✅ **Temporary credentials work** — with assumed-role/SSO creds the token embedded `X-Amz-Security-Token`, which is exactly the credential shape IRSA / EKS Pod Identity provide. Good signal that the real deployment model will work.

**MySQL driver requirement (confirmed via AWS docs + go-sql-driver docs):**
- 🔴 **MySQL IAM auth requires `allowCleartextPasswords=true` in the DSN**, alongside TLS. The `AWSAuthenticationPlugin` uses MySQL's cleartext client plugin, which `go-sql-driver/mysql` refuses by default (`ErrCleartextPassword`). AWS's own Go example DSN is `…?tls=true&allowCleartextPasswords=true`. The current MySQL DSN builder sets neither → **MySQL IAM auth fails 100% without this change.** This breaks the "client never knows about IAM" principle for MySQL (see [Open Design Decisions](#open-design-decisions)).

**Verified against live RDS (`eu-central-1`, MySQL 8.0.46 + PostgreSQL 16.14, db.t4g.micro, IAM auth enabled), using the exact drivers provider-sql ships (`go-sql-driver/mysql v1.10.0`, `lib/pq v1.12.3`):**

| # | Scenario | Result | Proves |
|---|----------|--------|--------|
| MySQL A | `tls=<rds-ca>` (verified) + `allowCleartextPasswords=true` | ✅ connects as `iamuser@%` | **Secure path that works** |
| MySQL A2 | `tls=skip-verify` + cleartext | ✅ connects | encrypted-but-unverified fallback works |
| MySQL B | `tls=<rds-ca>`, **no** cleartext | ❌ `this user requires clear text authentication…` | **cleartext flag is mandatory** |
| MySQL C | `tls=false` + cleartext | ❌ `Access denied` | **RDS rejects non-TLS** |
| MySQL D | `tls=true` (system roots) + cleartext | ❌ `x509: certificate signed by unknown authority` | 🔴 **`tls=true` does NOT work — RDS CA is not in the system trust store** |
| PG A | `sslmode=require` | ✅ connects as `iamuser` | plan's PG DSN works (encrypt, no CA verify) |
| PG A2 | `sslmode=verify-full` + RDS CA bundle | ✅ connects | secure verified path works |
| PG B | `sslmode=disable` | ❌ `pg_hba.conf rejects` | **RDS rejects non-TLS** |
| PG D | `sslmode=verify-full`, no bundle (system roots) | ❌ cert verify error | RDS CA not in system store |

🔴 **MAJOR CORRECTION — `tls="true"` for MySQL is wrong and would ship a broken feature.** RDS/Aurora server certs chain to Amazon's *RDS-specific* CAs (`rds-combined`/global bundle, 108 certs), which are **not** in the OS/Go system trust store. `go-sql-driver`'s `tls=true` verifies against system roots and therefore **fails to connect**. The fix is one of:
- **(secure, recommended)** register the Amazon RDS CA bundle as a `*tls.Config{RootCAs:…}` via `mysql.RegisterTLSConfig("rds", …)` and use `tls=rds`, or
- **(weaker)** `tls=skip-verify` (encrypted, no CA verification).

PostgreSQL/`lib/pq` is unaffected by this in the plan's current form because `sslmode=require` **encrypts without verifying the CA** — so it connects, but it is *not* verifying the server identity (use `verify-full` + bundle to harden). See [Open Design Decisions](#open-design-decisions) #5.

**Still unverified (needs a real provider deployment, not just a driver test):** TLS trust behaviour *inside the distroless provider image* (the RDS CA must be made available there too), and token regeneration across a reconcile >15 min apart (low risk — the provider builds a fresh connection per reconcile, and tokens are generated fresh each Connect()).

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
2. At Connect() time, call `auth.BuildAuthToken(ctx, "host:port", region, dbUser, creds)` from AWS SDK v2 — note the endpoint **must** include the port (verified: bare host errors)
3. The returned ~1.5 KB token (measured: 1547 B MySQL, 1536 B PG) is used AS the password in the DSN
4. SSL/TLS is required and auto-enforced — **RDS rejects non-TLS for both engines (verified).** MySQL additionally requires `allowCleartextPasswords=true` (the `AWSAuthenticationPlugin` uses the cleartext client plugin); PostgreSQL needs only `sslmode=require`. **MySQL cert verification needs the Amazon RDS CA bundle** — `tls=true` against the system store fails ([DD#5](#open-design-decisions))
5. AWS credentials are loaded via `config.LoadDefaultConfig` and discovered from the environment (Pod Identity, IRSA, instance metadata) — temporary/session credentials are supported (token embeds `X-Amz-Security-Token`)
6. `region` must be non-empty and is **not** validated by the SDK at token-generation time — resolve it explicitly (spec → secret → `cfg.Region`) and error if still empty

### Key Architectural Decision: Token Injection at Connect()

The `newDB` function signatures stay **unchanged for PostgreSQL**:
- PostgreSQL: `New(creds map[string][]byte, database, sslmode string) xsql.DB` — unchanged
- MySQL: `New(creds map[string][]byte, tls *string, binlog *bool) xsql.DB` — **must change** to carry the cleartext flag (see [Open Design Decisions](#open-design-decisions)); the token-as-password injection itself is signature-neutral, but `allowCleartextPasswords` cannot be expressed through the existing args.

Instead, **before** calling `newDB`, the Connect() method injects the generated IAM token into `creds[password]`. For PostgreSQL the client layer never knows about IAM — it just sees a password. For MySQL it additionally needs the cleartext signal. This minimizes blast radius.

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

// TokenBuilder matches auth.BuildAuthToken's signature so tests can stub it
// without real AWS credentials or network. Production wiring passes auth.BuildAuthToken.
type TokenBuilder func(ctx context.Context, endpoint, region, dbUser string,
    creds aws.CredentialsProvider, optFns ...func(*auth.BuildAuthTokenOptions)) (string, error)

// ResolveRegion returns the region from: spec field > secret "region" key > cfg.Region.
// NOTE: the SDK does NOT error on an empty region (verified) — the caller MUST treat
// an empty result as fatal, because the generated token would be silently rejected by RDS.
func ResolveRegion(specRegion *string, creds map[string][]byte, cfgRegion string) string

// InjectToken generates an IAM auth token and writes it as the password in creds.
// Reads endpoint, port, username from creds and assembles "host:port" (the SDK
// requires the port — a bare host errors). Returns an error if any key is missing
// or if region is empty. `build` is injectable for testing (pass auth.BuildAuthToken
// in production); `creds` is the aws.CredentialsProvider from a loaded aws.Config.
func InjectToken(ctx context.Context, secret map[string][]byte, region string,
    awsCreds aws.CredentialsProvider, build TokenBuilder) error
```

Design notes baked in from verification:
- **`host:port` assembly is mandatory** — `BuildAuthToken` errors on a bare host.
- **Region must be non-empty** — `InjectToken` returns an error rather than calling the SDK with `""`, since the SDK would otherwise emit a token RDS rejects.
- **`build TokenBuilder` is injected** so `TestInjectToken` runs with a static fake credentials provider and a stub builder — no AWS account, no network.
- Loading `config.LoadDefaultConfig(ctx)` (to get `aws.Config{Credentials, Region}`) happens **once in the reconciler/provider Connect path**, not inside `InjectToken`, keeping the package pure and testable. `cfg.Region` is then passed into `ResolveRegion` as the final fallback.

New dependency: `github.com/aws/aws-sdk-go-v2/config` (tested: `v1.32.25`) + `github.com/aws/aws-sdk-go-v2/feature/rds/auth` (tested: `v1.6.29`). This is the first cloud-SDK dependency in the repo — see [Open Design Decisions](#open-design-decisions) re: reviewer pushback on dependency weight.

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

Pattern (operate on `secretData` **after** `RemapCredentialKeys`, before `newDB`):
```go
secretData := xsql.RemapCredentialKeys(s.Data, pc.Spec.Credentials.SecretKeyMapping.ToMap())
cleartext := false
if pc.Spec.Credentials.Source == v1alpha1.CredentialsSourceAWSIAMAuth {
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, errors.Wrap(err, errLoadAWSConfig)
    }
    region := awsiam.ResolveRegion(pc.Spec.Credentials.Region, secretData, cfg.Region)
    if err := awsiam.InjectToken(ctx, secretData, region, cfg.Credentials, auth.BuildAuthToken); err != nil {
        return nil, errors.Wrap(err, errGenerateIAMToken)
    }
    // ⚠️ Do NOT set tls="true" — verified to FAIL against RDS (cert signed by
    // RDS CA not in the system store). Use the RDS-CA TLS config (see DD#5).
    rdsTLS := "rds"      // a TLS config registered with the Amazon RDS CA bundle
    tlsName = &rdsTLS
    cleartext = true     // MySQL AWSAuthenticationPlugin needs allowCleartextPasswords=true
}
return &external{db: c.newDB(secretData, tlsName, mg.Spec.ForProvider.BinLog, cleartext)}, nil
```
> Two MySQL-specific consequences, both verified against live RDS:
> - **`tls=true` is wrong** — it fails cert verification because the RDS CA isn't in the system trust store. The provider must register the Amazon RDS CA bundle (`mysql.RegisterTLSConfig("rds", &tls.Config{RootCAs: rdsPool})`) and reference it by name, or fall back to `tls=skip-verify`. See [Open Design Decisions](#open-design-decisions) #5. If the user has already configured the provider's existing custom-TLS mechanism with the RDS CA, prefer that.
> - The trailing `cleartext` arg reflects the MySQL `New`/`newDB` signature change ([DD#1](#open-design-decisions)). The DSN builder appends `&allowCleartextPasswords=true` only when set, so non-IAM callers are unaffected.

**PostgreSQL reconcilers** (6 files):
- `pkg/controller/cluster/postgresql/database/reconciler.go`
- `pkg/controller/cluster/postgresql/role/reconciler.go`
- `pkg/controller/cluster/postgresql/grant/reconciler.go`
- `pkg/controller/cluster/postgresql/extension/reconciler.go`
- `pkg/controller/cluster/postgresql/schema/reconciler.go`
- `pkg/controller/cluster/postgresql/default_privileges/reconciler.go`

Pattern (operate on `secretData` after `RemapCredentialKeys`). **Do not mutate `pc.Spec.SSLMode`** — the reconciler reads `clients.ToString(pc.Spec.SSLMode)` inline at the `newDB` call, so use a local override instead of mutating the fetched ProviderConfig object:
```go
secretData := xsql.RemapCredentialKeys(s.Data, pc.Spec.Credentials.SecretKeyMapping.ToMap())
sslMode := clients.ToString(pc.Spec.SSLMode)
if pc.Spec.Credentials.Source == v1alpha1.CredentialsSourceAWSIAMAuth {
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, errors.Wrap(err, errLoadAWSConfig)
    }
    region := awsiam.ResolveRegion(pc.Spec.Credentials.Region, secretData, cfg.Region)
    if err := awsiam.InjectToken(ctx, secretData, region, cfg.Credentials, auth.BuildAuthToken); err != nil {
        return nil, errors.Wrap(err, errGenerateIAMToken)
    }
    sslMode = "require"  // local override; force TLS for IAM auth (no spec mutation)
}
return &external{db: c.newDB(secretData, pc.Spec.DefaultDatabase, sslMode)}, nil
```

### 4. Namespaced provider helper changes (2 files)

**`pkg/controller/namespaced/mysql/provider/provider.go`**:
- Add `CredentialsSource` and `Cleartext bool` fields to `ProviderInfo` struct
- In both ProviderConfig and ClusterProviderConfig branches, capture the source (+ optional `Region`)
- After fetching/remapping the secret, if source is `AWSIAMAuth`:
  - `config.LoadDefaultConfig(ctx)` → resolve region (spec → secret → `cfg.Region`)
  - Call `awsiam.InjectToken(ctx, secretData, region, cfg.Credentials, auth.BuildAuthToken)`
  - Set `TLS = "rds"` (the RDS-CA-bundle TLS config — **not** `"true"`, which fails cert verify; see [DD#5](#open-design-decisions)) and `Cleartext = true` on the returned `ProviderInfo`
- ⚠️ The 3 namespaced MySQL reconcilers each call `c.newDB(providerInfo.SecretData, tlsName, binlog)` — once `newDB` gains the `cleartext` arg they must pass `providerInfo.Cleartext`. So "zero reconciler changes" holds for **PostgreSQL** but **not** MySQL: the 3 MySQL namespaced reconcilers each gain a one-arg change. (Still no *logic* change — they just forward the flag.)

**`pkg/controller/namespaced/postgresql/provider/provider.go`**:
- Add `CredentialsSource` (+ optional `Region`) to capture
- Same load-config + `InjectToken` pattern
- Force `SSLMode = "require"` on the returned `ProviderInfo` (this field is already returned and consumed, so the 6 PG namespaced reconcilers need **zero** changes)

This means **zero changes** to the 6 PostgreSQL namespaced reconcilers, and a **trivial one-arg forward** in the 3 MySQL namespaced reconcilers (consequence of the MySQL cleartext signature change, not of the injection itself).

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

- `pkg/clients/awsiam/awsiam_test.go` (all run with a stub `TokenBuilder` + static fake `aws.CredentialsProvider` — no AWS account/network):
  - `TestResolveRegion` — spec > secret "region" key > `cfg.Region` fallback; asserts empty result when all three are empty
  - `TestInjectToken` — stub builder; assert `secret[password]` equals the returned token and that the builder received `"host:port"` (endpoint+port assembled) and the dbUser from `secret[username]`
  - `TestInjectToken_MissingKeys` — error on missing endpoint/port/username
  - `TestInjectToken_EmptyRegion` — error returned **before** the builder is called (since the SDK won't guard it)
- MySQL DSN test in `pkg/clients/mysql/` — assert `allowCleartextPasswords=true` appears in the DSN **only** when the cleartext flag is set, and is absent otherwise (guards existing non-IAM users)

---

## File Change Summary

| Category | Files | Nature |
|----------|-------|--------|
| **New** | `pkg/clients/awsiam/awsiam.go` | Token generation + region resolution |
| **New** | `pkg/clients/awsiam/awsiam_test.go` | Unit tests (stubbed builder) |
| **API types** | 6 files in `apis/` | Add enum value + Region field |
| **MySQL client** | `pkg/clients/mysql/mysql.go` | `New`/`DSN` gain `cleartext bool`; append `allowCleartextPasswords=true` when set |
| **Cluster reconcilers** | 9 files in `pkg/controller/cluster/` | Token injection + load AWS config in Connect() |
| **Namespaced providers** | 2 files (`provider.go`) | Token injection in GetProviderConfig() |
| **Namespaced MySQL reconcilers** | 3 files | One-arg forward of `Cleartext` flag (consequence of MySQL signature change) |
| **Namespaced PostgreSQL reconcilers** | 0 files (!) | Changes fully absorbed by provider.go |
| **Dependencies** | `go.mod`, `go.sum` | AWS SDK v2 (`config`, `feature/rds/auth`) — first cloud SDK in repo |
| **Generated** | deepcopy + CRD YAMLs | `make generate` |
| **Examples** | 4 new YAML files | IAM auth configs |

**Total hand-written file changes: ~21 files** (the MySQL cleartext requirement adds the client file + 3 namespaced MySQL reconcilers vs. the original estimate).

---

## Verification

**Already proven (local, no infra):**
- `BuildAuthToken` signature, `host:port` requirement, empty-region silent-failure, `cfg.Region` fallback, and temporary-credential support — verified with a standalone Go probe against the real SDK (`config v1.32.25`, `auth v1.6.29`).
- Code-path audit confirming injection points and namespaced centralization (see [Verification Findings](#verification-findings-empirical)).

**Already proven (live RDS end-to-end, ephemeral instances, torn down):**
- Token acceptance for both engines, the MySQL `allowCleartextPasswords` requirement, the TLS-required behaviour, and the **`tls=true` cert-verification failure** that corrected the design — full matrix in [Verification Findings](#verification-findings-empirical). Done with the same drivers provider-sql ships.

**Still to do:**
1. `make reviewable` — must pass (lint, generate, test)
2. Unit tests for `pkg/clients/awsiam/` package + the MySQL cleartext DSN test
3. **In-cluster validation (the remaining gate):** prove the RDS CA bundle is trusted *inside the distroless provider image* (per [DD#5](#open-design-decisions)) and that IRSA/Pod-Identity credential discovery works in a real EKS deployment. Concretely:
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

---

## Open Design Decisions

These surfaced during verification and should be settled before/early in the PR (worth raising in the issue thread so the maintainer weighs in):

1. **How to thread `allowCleartextPasswords=true` into the MySQL DSN (REQUIRED for MySQL IAM to work at all).**
   The DSN is built in `pkg/clients/mysql/mysql.go`; the client otherwise has no notion of IAM. Setting it globally is unsafe — for non-IAM users running `tls=preferred` (no cert verification) it would let a MITM server harvest the password via a forced cleartext request. So it must be conditional.
   - **Recommended:** add a `cleartext bool` parameter to `mysql.New` / `DSN` (and the `newDB` func field), set only on the IAM path. Lowest-magic, explicit, easy to test. Cost: the 3 cluster + 3 namespaced MySQL reconcilers' `newDB` signatures change (mechanical).
   - Alternative: a variadic functional option (`mysql.New(creds, tls, binlog, opts...)`) — keeps existing call sites compiling, but the `newDB` field type still changes, so the churn is similar. Slightly more idiomatic, slightly less greppable.
   - Rejected: sentinel key in the creds map (`creds["__iam"]`) — hidden coupling, hard to follow.

2. **First cloud-SDK dependency in the repo.** `aws-sdk-go-v2/config` + `feature/rds/auth` pull in the AWS SDK core/credentials/IMDS modules. provider-sql currently has no cloud SDK. A maintainer may object on dependency-weight grounds. Pre-empt in the PR description; if it's a blocker, the fallback is the #393 credential-helper pattern (provider stays SDK-free, an external sidecar mints tokens) — but that's a different feature, not this one.

3. **Where to call `config.LoadDefaultConfig`.** Currently proposed per-`Connect()` (matches the provider's stateless, fresh-connection-per-reconcile model). It does env/IMDS lookups each time. Acceptable for v1; note it as a possible future optimization (cache the `aws.Config`) rather than premature complexity now.

4. **Forcing TLS/SSL silently overrides a user's explicit `sslMode: disable`.** Intentional (IAM mandates TLS — verified: RDS rejects non-TLS for both engines), but should be documented so it isn't surprising. Consider a warning event/log when an IAM ProviderConfig had a weaker SSL setting that we overrode.

5. **🔴 RDS CA trust — how does the MySQL path verify the server cert? (highest-impact open decision, found via live testing.)**
   `tls=true` was empirically proven to **fail** against RDS (`x509: certificate signed by unknown authority`) — the Amazon RDS CA bundle is not in the system/Go trust store. So forcing `tls=true` would ship a feature that cannot connect. Options:
   - **(a) Embed the Amazon RDS global CA bundle** (`//go:embed`, ~165 KB, 108 certs from `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`) and register it (`mysql.RegisterTLSConfig`) so IAM auth is **secure by default with zero user config**. Cost: a vendored cert bundle the repo must refresh periodically as AWS rotates CAs.
   - **(b) Reuse the provider's existing custom-TLS mechanism** (`tls: custom` + a TLS secret containing the CA) — no vendoring, but the user must supply the RDS CA themselves; more setup, easy to get wrong.
   - **(c) `tls=skip-verify`** — encrypted but **unverified** (no protection against a spoofed RDS endpoint). Simplest, weakest. Notably this is the *de facto* posture PostgreSQL is already in here, since `lib/pq sslmode=require` also does not verify the CA (verified).
   - **Recommendation:** (a) for MySQL (secure default, matches what AWS's own tooling does), and document (b) for users who want to manage the CA themselves. For PostgreSQL, keep `sslmode=require` for v1 (works, and matches common RDS-IAM examples) but document `verify-full` + the bundle as the hardening path. **Raise this explicitly in the issue thread — it affects the example manifests and possibly the provider image.**

---

## References

- Issue #347 — AWS IAM DB auth (this work): https://github.com/crossplane-contrib/provider-sql/issues/347
- Issue #393 — pluggable credential-helper source: https://github.com/crossplane-contrib/provider-sql/issues/393
- Issue #106 (closed) — earlier RDS IAM request + community workaround: https://github.com/crossplane-contrib/provider-sql/issues/106
- AWS — Creating a database account using IAM authentication (the `GRANT rds_iam` / `AWSAuthenticationPlugin` SQL): https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.DBAccounts.html
- AWS — IAM database authentication overview (TLS required; `rds_iam` disables password auth): https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
- AWS — Connecting with IAM auth and the SDK for Go (the `tls=true&allowCleartextPasswords=true` DSN): https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.IAMDBAuth.Connecting.Go.html
- AWS SDK v2 `feature/rds/auth` (`BuildAuthToken`): https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/feature/rds/auth
- `go-sql-driver/mysql` (`allowCleartextPasswords`, `ErrCleartextPassword`): https://pkg.go.dev/github.com/go-sql-driver/mysql
- EKS Pod Identity: https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html
- IRSA (IAM roles for service accounts): https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
