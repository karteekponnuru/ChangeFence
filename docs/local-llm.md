# Local AI red-team hypotheses

ChangeFence can use a local LLM through Ollama to propose security attack hypotheses without sending the agent architecture to a hosted model.

The design deliberately separates **reasoning** from **verification**:

```text
Local LLM (Ollama)
        |
        | proposes hypotheses
        v
ChangeFence deterministic verifier
        |
        +--> VERIFIED_NEW
        +--> VERIFIED_EXISTING
        +--> UNREACHABLE
```

The model is allowed to ask, for example:

> Could a poisoned supplier message influence the Procurement Agent, which then delegates to Finance and reaches `payment.execute`?

The model's proposed path is not trusted. ChangeFence independently checks the baseline and candidate capability graphs. If the capability is not actually reachable, the hypothesis is marked `UNREACHABLE`.

## Run locally

1. Install and start Ollama.
2. Make sure a local model is available, for example `gemma3`.
3. Run:

```bash
changefence hypothesize \
  examples/procurement-base.yaml \
  examples/procurement-candidate.yaml \
  --model gemma3
```

Ollama is expected at `http://localhost:11434` by default. A different local endpoint can be supplied with `--url`.

## Why local

- the architecture can stay on the user's machine
- no hosted-model API key is required for hypothesis generation
- different local models can be compared
- the deterministic ChangeFence verifier remains the security authority regardless of model quality

## What the LLM does not decide

The LLM does not determine whether a release is secure, whether an authority path exists, or whether a security invariant is violated. Those decisions remain deterministic.
