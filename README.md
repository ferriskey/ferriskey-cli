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

Supabase has no realm and no OIDC client, so the import carries **users and
their roles**, and nothing else. The realm name comes from `--target-realm` (or
`--source-realm`) and defaults to `supabase`.

**Passwords are not migrated.** Supabase keeps bcrypt hashes in
`auth.users.encrypted_password` and does not serve them over the Admin API, and
the FerrisKey API accepts only a plaintext password — neither side exposes a
hash. Imported users arrive without credentials and have to go through a
password reset.

Usernames are derived from the full email address, falling back to the phone
number and then to the Supabase user id, since Supabase users have no username
of their own.

#### Roles

Supabase has no role catalogue. Roles are read from each user's `app_metadata`,
which is where applications conventionally keep them — either as a `roles` array
or as a single `role` string. Both are read and merged:

    "app_metadata": { "provider": "email", "roles": ["admin", "billing"] }
    "app_metadata": { "provider": "email", "role": "admin" }

Every distinct role named by an imported user becomes a realm role. The
catalogue is built from the users that survived the filters above, so a role
held only by a soft-deleted or unconfirmed account is not created.

Supabase attaches no description or permission to a role, so imported roles
carry a name and nothing else. Permissions have to be granted in FerrisKey
afterwards.

The top-level `user.role` field is **not** imported. It is the Postgres RLS
role, `authenticated` for virtually every account, and importing it would create
a single realm role held by the entire directory.

A role name containing `:` is rejected with an error naming the role and the
user. A realm blueprint reserves that character for client-scoped roles
(`client_id:role_name`), and Supabase defines no clients, so such a name cannot
be expressed. Rename it in `app_metadata` before importing.

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
