# Contributing

Thanks for helping. Bug reports, fixes and small improvements are welcome. For anything larger, or
anything that changes what the agent sends to bynh, open an issue first so we can agree on the
approach.

## Ground rules

- **The protocol is a contract.** [PROTOCOL.md](PROTOCOL.md) is shared with the bynh platform. Changes
  to it need agreement from both sides; propose them in an issue.
- **Safety first.** Code that connects anywhere must go through `Net::connect`, which resolves once and
  applies the private-address rules. Never log tokens, monitor credentials or header values.
- **Small and dependable.** Prefer the standard library and the crates already in use. A new
  dependency needs a good reason; it ends up in every customer network.
- **Security issues** go to security@bynh.io, not to the issue tracker (see [SECURITY.md](SECURITY.md)).

## Development

```sh
cargo build
cargo test                                  # unit and integration tests, all local
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo run -- check https://example.com      # try a check by hand
```

The integration tests start a mock platform and local target servers on 127.0.0.1; they need no
network access except one DNS test, which accepts a timeout when offline.

## Pull requests

- One topic per pull request, with tests for new behaviour.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` must pass (CI runs
  them on Linux, macOS and Windows).
- Commit messages: a short imperative subject in sentence case, no trailing period
  (“Fix redirect handling for relative locations”). Add a body when the reason isn’t obvious.
- Update `CHANGELOG.md` under “Unreleased” for anything users will notice.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
