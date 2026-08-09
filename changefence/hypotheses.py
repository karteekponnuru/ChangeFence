import json
import urllib.error
import urllib.request
from dataclasses import asdict
from .engine import analyze, index_by_pair


class HypothesisError(RuntimeError):
    pass


HYPOTHESIS_SCHEMA = {
    "type": "object",
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "source_agent": {"type": "string"},
                    "target_capability": {"type": "string"},
                    "attacker_control": {"type": "string"},
                    "rationale": {"type": "string"},
                    "proposed_path": {"type": "array", "items": {"type": "string"}},
                },
                "required": [
                    "id", "title", "source_agent", "target_capability",
                    "attacker_control", "rationale", "proposed_path"
                ],
            },
        }
    },
    "required": ["hypotheses"],
}


def _architecture(spec):
    return {
        "system": spec.name,
        "agents": {
            name: {
                "model": agent.model,
                "prompt_id": agent.prompt_id,
                "tools": list(agent.tools),
                "delegates_to": list(agent.delegates_to),
            }
            for name, agent in spec.agents.items()
        },
        "tools": {
            name: {"capabilities": [asdict(cap) for cap in tool.capabilities]}
            for name, tool in spec.tools.items()
        },
        "invariants": [asdict(inv) for inv in spec.invariants],
    }


def build_hypothesis_prompt(base, candidate, count=6):
    payload = {"baseline": _architecture(base), "candidate": _architecture(candidate)}
    return f"""
You are a defensive AI red-team analyst helping review a proposed AI-agent release.
Generate up to {count} concrete attack hypotheses caused or enabled by the candidate system.

Rules:
- Use ONLY agent names and capability names present in the supplied architecture.
- Focus on security-relevant composition: prompt injection, poisoned tool or data input,
  delegation abuse, confused-deputy behavior, data exfiltration, privilege expansion,
  unsafe state changes, and cross-agent authority.
- A hypothesis is only a hypothesis. Do NOT claim it is verified.
- Prefer hypotheses that could be new in the candidate compared with the baseline.
- source_agent must name the agent whose effective authority should be checked.
- target_capability must be an exact capability string from the architecture.
- proposed_path is your suggested conceptual path; it will be independently verified.
- Return only structured JSON matching the supplied schema.

ARCHITECTURE:
{json.dumps(payload, indent=2)}
""".strip()


def _ollama_request(model, prompt, base_url="http://localhost:11434", timeout=120):
    endpoint = base_url.rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You generate defensive attack hypotheses for AI-agent security review. "
                    "Never treat your own proposed path as verified evidence."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": HYPOTHESIS_SCHEMA,
        "options": {"temperature": 0.2},
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise HypothesisError(
            f"Could not reach Ollama at {base_url}. Start Ollama locally and try again. ({exc})"
        ) from exc
    except json.JSONDecodeError as exc:
        raise HypothesisError("Ollama returned invalid JSON.") from exc

    try:
        content = raw["message"]["content"]
        parsed = json.loads(content)
        hypotheses = parsed["hypotheses"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HypothesisError("Ollama response did not match the expected hypothesis format.") from exc

    if not isinstance(hypotheses, list):
        raise HypothesisError("Ollama response did not contain a hypothesis list.")
    return hypotheses


def verify_hypotheses(base, candidate, hypotheses):
    base_idx = index_by_pair(analyze(base))
    candidate_idx = index_by_pair(analyze(candidate))
    verified = []

    for item in hypotheses:
        src = str(item.get("source_agent", ""))
        cap = str(item.get("target_capability", ""))
        pair = (src, cap)

        if pair in candidate_idx and pair not in base_idx:
            verdict = "VERIFIED_NEW"
            evidence_path = list(candidate_idx[pair].path)
        elif pair in candidate_idx:
            verdict = "VERIFIED_EXISTING"
            evidence_path = list(candidate_idx[pair].path)
        else:
            verdict = "UNREACHABLE"
            evidence_path = []

        verified.append({**item, "verification": verdict, "evidence_path": evidence_path})

    return verified


def generate_attack_hypotheses(
    base,
    candidate,
    model="gemma3",
    count=6,
    base_url="http://localhost:11434",
    timeout=120,
    requester=None,
):
    prompt = build_hypothesis_prompt(base, candidate, count=count)
    requester = requester or _ollama_request
    proposed = requester(model=model, prompt=prompt, base_url=base_url, timeout=timeout)
    verified = verify_hypotheses(base, candidate, proposed[:count])

    summary = {
        "generated": len(verified),
        "verified_new": sum(1 for h in verified if h["verification"] == "VERIFIED_NEW"),
        "verified_existing": sum(1 for h in verified if h["verification"] == "VERIFIED_EXISTING"),
        "unreachable": sum(1 for h in verified if h["verification"] == "UNREACHABLE"),
    }
    return {
        "engine": "ollama",
        "model": model,
        "base": base.name,
        "candidate": candidate.name,
        "summary": summary,
        "hypotheses": verified,
    }
