# Contributing

[한국어](CONTRIBUTING.md)

Thank you for your interest in Deplite Agent.

This document explains how to report bugs and request features.

## Pull request policy

Deplite is a commercial service, and this repository is a client for using it.

Because of our licensing policy and maintenance capacity, we are not able to merge pull requests from outside the team.

Please open an issue instead. We review every issue and make the change ourselves, so reports and requests are genuinely useful to us.

## Reporting a bug

Including the following helps a lot in narrowing down the cause.

- Steps to reproduce, reduced as far as you can
- Your environment — operating system, Go version, agent version
- What you expected and what actually happened
- The full error message or stack trace

Please redact tokens and install codes before posting, as they may appear in logs.

## Requesting a feature

Tell us what you were trying to do and how you are working around it today.

Describing the situation usually leads to a better design than proposing a specific solution up front.

## Checking the behavior yourself

You can build the repository locally to narrow down what you are seeing.

Go 1.23 or later is required.

```sh
go build ./...
go test -race ./...
```

The test suites run entirely locally, so no Deplite account or external environment is needed.

## Security vulnerabilities

Please do not report security vulnerabilities through public issues.

Use the [private report form](https://github.com/Deplite/agent/security/advisories/new) under the repository's Security tab, and we will follow up with you.

## License

This project is distributed under the Apache License 2.0.
