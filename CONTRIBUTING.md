# Contributing to tai42-identity-oidc

`tai42-identity-oidc` is the validate-only OIDC **identity provider** for the TAI
ecosystem. The hard rule (the plugin rule): **it depends on `tai42-contract` +
`tai42-kit` only and never imports the skeleton.** The provider registers itself as
`"identity-oidc"` in the contract's module-level identity-provider registry at
import — there is no import edge to the skeleton in either direction.

## Ground rules

- **No skeleton import — ever.** The package is contract-facing; the ban is
  enforced by ruff (`flake8-tidy-imports`), so a stray import fails lint:
  ```bash
  grep -rn "tai42_skeleton" src/   # must be empty
  ```
- **Validate-only.** This provider mints no keys and holds no state: it
  implements the base `IdentityProvider` ABC, **not** `ApiKeyIdentityProvider`.
- **Loud, fail-closed errors.** No swallowed exceptions, silent fallbacks, or
  silent truncation. A JWT-shaped token that fails verification **raises** and the
  request denies; an unreachable/broken issuer is caught loudly by
  `healthcheck()` at startup.
- **Typed package** (`py.typed`). Pyright runs clean.

## Layout

- `src/tai42_identity_oidc/provider.py` — the `OidcIdentityProvider` (JWT
  validation against the issuer's JWKS), its `OidcIdentitySettings`, and the
  module-level registration.
- `tests/` — the provider's behavior against a local loopback OIDC issuer with
  in-test RSA keys.

## Naming

PyPI is a flat namespace with no owner in the path, so distributions carry the
`tai42-` prefix. GitHub repositories keep their `tai-` names, because the
`tai42ai` organisation already namespaces them. Import packages follow the
distribution.

| Surface | Form |
| --- | --- |
| Distribution — PyPI, `pip install`, dependency pins | `tai42-<name>` |
| Import package | `tai42_<name>` |
| GitHub repository | `tai-<name>` |

So a dependency is declared as `tai42-<name>` while its repository is named
`tai-<name>`, and both spellings are correct in their own context.

Some surfaces are deliberately neither, and must not be renamed: the `tai` CLI
command (`tai42` is an alias), the Prometheus metric namespace (`tai_tool_*`),
`TAI_*` environment variables, and the `tai-plugin.yml` descriptor filename.

## Dev

```bash
uv venv --python 3.13
uv pip install --no-sources --editable ".[dev]"
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv run --no-sync pyright
uv run --no-sync pytest --cov --cov-report=term-missing
```

`make dev` installs the sibling `tai-contract` and `tai-kit` repos as editable installs for local cross-repo development.

Before any commit, run a secret scan over `src/` and `tests/` (e.g.
`detect-secrets scan`).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
