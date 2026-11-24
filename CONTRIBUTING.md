# Contributing

Thanks for considering a contribution. RampartEye aims to stay small, safe and well tested, so
a short discussion before larger changes saves everybody time.

## Before you start

- **Bugs:** open an issue with the version, what you did, what you expected and what happened.
  Logs help (`docker compose logs app`); remove addresses and names you do not want to share.
- **Features:** open an issue first. Check [ROADMAP.md](ROADMAP.md): some things are deliberately
  out of scope.
- **Security problems:** do not open an issue; see [SECURITY.md](SECURITY.md).
- **Signatures** are the easiest way to contribute: see [docs/SIGNATURES.md](docs/SIGNATURES.md).
  A new built-in needs a test fixture (a captured response in `internal/sig/testdata/fixtures`)
  showing that it matches, and should not match unrelated services.

## Making a change

1. Read [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
2. Write the test first, watch it fail, then make it pass. Tests use
   [ctx42/testing](https://github.com/ctx42/testing) only.
3. Run `make test`; run `make test-integration` when you touch the store or migrations,
   `make css` when you touch templates or styles, and `make e2e` when you touch scanning,
   diffing or the lab.
4. Keep commits small, with messages like `fix(web): escape banner in service page`
   (`type(scope): short lowercase imperative subject`, at most 60 characters).
5. Open a pull request describing what changed and why, and how you tested it.

## Ground rules

- The safety model is not negotiable: no request methods other than `GET`/`HEAD`, no request
  bodies, no payloads, nothing outside the configured scope. See
  [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).
- English only, in code, comments, UI and docs.
- No new runtime dependencies without a good reason; no Node.js in the build.
- Do not copy code from projects whose licence does not allow it.

By contributing you agree that your contribution is licensed under the [MIT licence](LICENSE).
