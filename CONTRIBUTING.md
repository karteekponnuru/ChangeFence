# Contributing

Contributions are welcome, especially new agent-security scenarios, framework importers, policy checks, tests, and clearer explanations.

1. Fork the repository.
2. Create a focused branch.
3. Add or update tests.
4. Run `pytest`.
5. Open a pull request explaining the security problem and the proposed change.

Please keep findings deterministic where possible. If an LLM is used to generate candidate attacks, a deterministic verifier should decide whether a reported authority path or policy violation is real.
