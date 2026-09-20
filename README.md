# ferris-ctl

Official CLI for FerrisKey IAM.

## Install

cargo install ferris-ctl

## Usage

ferris-ctl realm list
ferris-ctl realm create myrealm

## Importing a realm

`ferris-ctl realm import` pulls a realm description out of an external system
and replays it against FerrisKey. Available sources: `config` (a YAML or TOML
file, see `examples/realm.yaml`), `keycloak`, `zitadel`, and `supabase`.

Add `--dry-run` to any import to resolve the source and print what would be
created without calling FerrisKey. A dry run needs neither a configured context
nor authentication, so it is the cheapest way to check a mapping.

An import converges: re-running it skips what the realm already has rather than
failing or duplicating.

### Supabase

Reads a project through its Auth (GoTrue) Admin API, authenticating with the
project's `service_role` key.

    ferris-ctl realm import \
      --from supabase \
      --source-url https://<project>.supabase.co \
      --source-token <service_role key> \
      --target-realm my-realm

Supabase has no realm, no OIDC client and no role catalogue of its own, so the
import carries **users only**. The realm name comes from `--target-realm` (or
`--source-realm`) and defaults to `supabase`.

**Passwords are not migrated.** Supabase keeps bcrypt hashes in
`auth.users.encrypted_password` and does not serve them over the Admin API, and
the FerrisKey API accepts only a plaintext password — neither side exposes a
hash. Imported users arrive without credentials and have to go through a
password reset.

Usernames are derived from the full email address, falling back to the phone
number and then to the Supabase user id, since Supabase users have no username
of their own.

Three kinds of account are dropped by default, each re-enabled by its own flag:

| Flag | Keeps |
|------|-------|
| `--source-include-deleted` | Accounts an operator soft-deleted (`deleted_at` set, row still present) |
| `--source-include-anonymous` | Anonymous sign-in sessions, which have neither email nor phone |
| `--source-include-unconfirmed` | Accounts that never confirmed an email or a phone number |

`--source-include-anonymous` is not undone by the confirmation filter: an
anonymous account has nothing to confirm, so it is governed by that flag alone.

### Reusable sources

Connection details can be stored once and referenced by name:

    ferris-ctl source add supa --kind supabase \
      --url https://<project>.supabase.co --token <service_role key>
    ferris-ctl realm import --source-ref supa --target-realm my-realm

Inline `--source-*` flags override individual fields of a stored source. The
Supabase account filters above are deliberately not stored: they are per-run
choices, so a saved source can never silently widen a later import.
