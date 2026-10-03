# Security policy

bynh-status-agent runs inside customer networks, so we take reports seriously and answer them
quickly.

## Reporting a vulnerability

Email **security@bynh.io** with:

- what you found and where (file, function, version or commit),
- how to reproduce it, and
- what an attacker could do with it.

Please don’t open a public issue, pull request or discussion for a vulnerability. We acknowledge
reports within two business days, keep you updated while we work on a fix, and credit you in the
release notes if you’d like.

## Scope

In scope: this repository, the release binaries and the container image built from it. Examples of
what we want to hear about:

- reaching private or internal addresses without `allow_private` (including through redirects, DNS
  tricks or unusual address forms),
- leaking the agent token or monitor credentials (logs, error messages, other hosts),
- anything that lets the platform, a monitored target or a network attacker run code on, crash or
  exhaust the agent’s host,
- weaknesses in the installer, the systemd unit or the image.

The bynh platform itself (api.bynh.io and the web app) is covered by the same address.

## Supported versions

Security fixes go into the latest release. Upgrade by pulling the newest image tag or running
`install.sh` again.
