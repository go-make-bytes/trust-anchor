# The database schema trust-anchor reads

The Postgres backend of this service never touches a table. It connects as an
`EXECUTE`-only role and reaches a dedicated `trust_anchor` schema through four
`SECURITY DEFINER` procedures — `save_snapshot`, `load_latest_snapshot`,
`save_bootstrap`, `load_latest_bootstrap` — each taking and returning a single
`jsonb` envelope. This directory is that schema: the two versioned tables, the
procedures, the privilege grants, and the small shared helpers they use.

Apply it as it is, or port it to your own migration tooling. Nothing here is
specific to how we deploy the service.

**Generated, not edited.** These files are produced from the repository that
authors the schema, and a check regenerates and diffs them, so a change made here
is reported as drift rather than quietly kept. Fix the schema at its source.

## Layout

| path | what |
|---|---|
| `trust_anchor/` | the schema this service uses — `V1__` creates the tables and the role grants, `R__` holds the four procedures and is re-applied whenever it changes |
| `util/` | shared helpers the procedures call: an identifier generator and the success/error envelope they return. `V2`/`V3` add identity helpers that this service never calls; they travel because a location is applied as a whole directory |
| `grants/` | database-wide hardening and per-schema human read roles, applied last. Removing `TEMPORARY` from `PUBLIC` and pinning the database's default `search_path` are what stop a caller influencing name resolution inside a privileged procedure body |
| `migrate.sh` | applies the locations in order with [Flyway](https://flyway.org), one history table per schema, and fails before touching the database if a requested location is missing |
| `provision-roles.sh` | creates the login role the service connects as. Run it **before** migrating: the migrations assign privileges and carry no credentials |
| `THIRD-PARTY-NOTICES.md` | the notice for the one third-party function included here |

## Applying it

Roles first — the migrations grant privileges to a role that must already exist.
Both scripts take everything from the environment, so the same files apply to any
database name or owner:

```sh
SERVICE_ROLES="trust_anchor_public:TRUST_ANCHOR_PUBLIC_PW" \
TRUST_ANCHOR_PUBLIC_PW="…" \
PGHOST=… PGDATABASE=… PGUSER=<owner> PGPASSWORD=… \
  ./provision-roles.sh
```

Then the migrations, in the stock Flyway image:

```sh
docker run --rm -v "$PWD:/db" \
  -e LOCATIONS="util trust_anchor grants" \
  -e PGHOST=… -e PGDATABASE=… -e PGUSER=<owner> -e PGPASSWORD=… \
  --entrypoint /bin/sh flyway/flyway:11-alpine /db/migrate.sh
```

`LOCATIONS` is the apply order, and `util` has to come before `trust_anchor`: the
schema's tables and procedures reference it directly, so applying `trust_anchor`
against a database with no `util` schema fails before anything is created. The
migrating user is the **owner**, never a superuser, so the objects end up owned by
the deployment role; the service then connects with `trust_anchor_public` and the
password given above, which is what `TRUST_STORE_DSN` carries.

Re-running either script is a no-op — the second migration pass reports nothing to
do, and the role script re-applies the password rather than failing.

## Licensing

The `trust_anchor` schema is MIT, like the rest of this repository, and says so in
its own files. `util` contains one function derived from third-party Apache-2.0
work; its notice travels in the file and the licence text is in
`THIRD-PARTY-NOTICES.md` beside it.
