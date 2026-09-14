# Secure AI SecOps Copilot lab threat model

Status: implemented lab design
Scope: synthetic, model-independent control-plane simulation
Out of scope: production model selection, model-provider security, and claims about jailbreak resistance

## System summary

The lab tests a security boundary for a future SecOps copilot. A model or other
planner may propose retrievals, text output, and tool calls, but its plan is
always treated as untrusted. A deterministic policy gateway decides whether the
plan is allowed, encoded, rate-limited, blocked, or staged for human approval.

The bundled scenarios are pre-authored. Running the lab does not contact an AI
provider, execute a tool, change a finding, or send data over the network.

```text
                         TRUSTED CONTROL PLANE
 Analyst ──> authenticated UI ──> API ──> policy gateway ──> approved read tools
                                             │
                                             ├──> approval queue for write tools
                                             └──> audit event / blocked result
                         ▲
                         │ candidate plan (untrusted)
                  model / planner boundary
                         ▲
                         │ prompt context
 UNTRUSTED DATA ──> scanner findings + retrieved runbooks
```

## Assets and security objectives

| Asset | Objective |
|---|---|
| Finding data and tenant metadata | Prevent cross-tenant access and unintended disclosure |
| Finding status, severity, and ownership | Prevent silent or unauthorized state changes |
| Integration credentials | Keep credentials outside prompts, responses, and tool arguments |
| Analyst identity and intent | Bind every access and approval to the authenticated user context |
| Tool capabilities | Keep the agent inside an explicit, least-privilege allowlist |
| Availability and cost | Bound tokens, iterations, time, and external calls |
| Audit trail | Record policy decisions without storing secrets or unnecessary prompt content |

## Actors and assumptions

- An authenticated analyst can request summaries and remediation drafts.
- An attacker may control text imported from a scanner, ticket, repository, or runbook.
- A future model provider may return an incorrect or adversarial candidate plan.
- The existing dashboard proxy and API-key boundary remain in place.
- The lab uses synthetic tenants, findings, recipients, and secrets only.
- The model is not an authorization authority and the system prompt is not a secret store.

## Trust boundaries and entry points

1. Imported finding text crossing from scanners into prompt context.
2. Retrieved documents crossing from a content store into prompt context.
3. Candidate model output crossing into the deterministic policy gateway.
4. Tool arguments crossing from the gateway into application services.
5. Generated text crossing into the browser renderer.
6. Authenticated browser requests crossing the Next.js proxy into the API.

## Prioritized abuse cases

| ID | Abuse case | Likelihood | Impact | Primary control | Verification |
|---|---|---:|---:|---|---|
| AI-01 | Indirect injection requests outbound exfiltration | High | High | Tool allowlist, deny-by-default egress, DLP | `indirect-finding-injection` |
| AI-02 | Retrieval returns another tenant's records | Medium | Critical | Tenant filter before retrieval and per-tool authorization | `cross-tenant-retrieval` |
| AI-03 | Agent closes or reassigns a finding without consent | High | High | Human approval for every write action | `unapproved-status-change` |
| AI-04 | Generated markup triggers a browser request or script | Medium | High | Plain-text rendering and output encoding | `unsafe-markdown-rendering` |
| AI-05 | Prompt, output, or arguments disclose a credential | Medium | Critical | Secret exclusion, canaries, output and argument DLP | `synthetic-secret-disclosure` |
| AI-06 | Agent loops consume excessive tokens or time | High | Medium | Token, step, time, and request budgets | `unbounded-tool-loop` |
| AI-07 | Poisoned runbook redirects data to an attacker | Medium | High | Provenance labels and tool allowlist | `poisoned-runbook` |
| AI-08 | Model smuggles undeclared tool parameters | Medium | High | Exact schemas with unknown fields rejected | `tool-schema-smuggling` |

## Control decisions

- Retrieval authorization is applied before content reaches the model.
- Every candidate plan is untrusted, even when it follows the system prompt.
- Read tools use exact schemas and tenant-bound resource identifiers.
- Write tools are staged for explicit human approval; the model cannot approve itself.
- External communication tools are absent from the copilot allowlist.
- Outputs are rendered as inert text and checked for synthetic secret canaries.
- Execution stops when token or iteration budgets are exceeded.
- Policy results explain the enforcing control without exposing hidden prompts or secrets.

## Residual risks

- The corpus demonstrates control behavior; it does not measure a live model's resistance to adaptive attacks.
- Pattern-based secret detection cannot identify every sensitive value. Production deployments require structured data classification and credential isolation.
- Human approval can become ineffective if the interface hides parameters or encourages blind confirmation.
- A compromised policy service or application authorization layer remains a high-impact boundary.
- Availability limits need production traffic and cost data before final thresholds are selected.

## Required production validation

Before connecting a model or real tool, add provider-specific red-team cases,
tenant-isolation integration tests, immutable approval records, audit-log
redaction tests, timeout enforcement, model-provider retention review, and a
documented incident-response path for AI-assisted actions.
