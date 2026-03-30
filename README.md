# AILogic — Security Policy for AspisProject

> Official repository for security policies, controls, and validations applied to AI-driven decisions in the AspisProject pipeline.

## Context

In the AspisProject flow (`user input → AI decision → backend execution → data cleaning → explanation → UI`), **AILogic** covers **exclusively the security of the AI decision layer**, *before* any interaction with the backend or UI.

This is *not* general cybersecurity: it does not cover infrastructure, networks, or authentication. It focuses on **robustness, traceability, and compliance of model decisions**.

## Scope of Responsibility (Sara)

As AI Security Lead, I define, document, verify, and enforce:

| Domain | What it covers | Concrete examples |
|--------|----------------|-------------------|
| Adversarial robustness | Resistance to manipulated inputs designed to corrupt decisions | Testing against prompt injection, jailbreak attempts, and token smuggling on user inputs before AI processing |
| Input confidentiality | Protection of sensitive user-provided data | Automatic redaction/masking of PII (names, emails, IDs) before model ingestion; audit of input logs |
| Traceability & justification | Ability to link each AI decision to its input, model, version, and compliance rule | Mandatory logging fields: `input_hash`, `model_id`, `decision_timestamp`, `rule_triggered` |
| Pre-backend compliance | Validation that a decision is *safe to execute* before being passed to backend | Automated checklist: ✅ no shell commands, ✅ no sensitive data exposed, ✅ aligned with ethical guardrails |

## Immediate Next Steps (Week 1)

✅ 1. Implement basic input sanitization: reject inputs containing shell operators (`;`, `|`, `$(`) or dangerous keywords (`rm -rf`, `curl http://`, `eval(`).  
✅ 2. Add mandatory trace fields to AI request payload: `"trace_id": "<uuid>", "source_context": "user_chat_v1"`.  
✅ 3. Create first compliance rule file: `rules/001-no-shell-execution.yaml` (template provided in next artifact).

## Repository Structure

```
AILogic/
├── README.md                    ← This file
├── SECURITY_POLICY.md           ← Formal policy (to be added next)
├── rules/
│   └── 001-no-shell-execution.yaml  ← First compliance rule example
├── tests/
│   └── adversarial/
│       └── basic_prompt_injection.py  ← First automated test
└── docs/
    └── onboarding.md            ← Onboarding guide for new contributors
```
