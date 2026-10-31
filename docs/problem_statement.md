# Problem statement

## The problem

Cloud services are configurable in many ways, and an individual setting can affect data exposure, service availability, or the ability to investigate an incident. A learner, small-team cloud operator, or hackathon participant may need to decide whether a configuration deserves attention and understand what evidence supports that decision. A short rule result without context can be hard to verify; a long policy document can be difficult to translate into a specific configuration review.

CloudShield AI explores a small, explainable workflow for five AWS-style configuration checks: public S3 access controls, S3 default encryption, security-group ingress to selected management ports, broad IAM policy wildcards, and basic CloudTrail trail settings. The intended output is a rule ID, severity, evidence from inspected fields, and a concise explanation—not an unsupported claim that a resource is exploitable.

## Target users and difficulties

- **Cloud security beginners and students** need concrete examples that connect a rule to the fields it reads and the reason it reports.
- **Small cloud teams and hackathon builders** need a repeatable, reviewable starting point that can be tested locally before considering account integrations.
- **Security reviewers** need findings that point to evidence and clearly separate a risky signal from proof of impact.

Common difficulties include interpreting nested policy data, distinguishing a permissive-looking setting from effective access, prioritizing issues without treating every public-facing service as unsafe, and knowing where a simplified check stops. Newcomers may also struggle to reproduce a result unless the input and expected output are small and deterministic.

## How existing approaches generally work

Cloud providers and third-party products offer configuration guidance, policy evaluation, inventory, posture management, and automated checks. AWS documentation describes controls such as S3 Block Public Access, IAM policy evaluation, security-group rules, and CloudTrail. These capabilities are complementary to this prototype; CloudShield AI does not claim that existing tools lack them or replace them.

For learning and prototyping, an operator often has to move between configuration data, provider documentation, and a finding explanation. The demonstrable usability gap this project targets is narrower: in a single local fixture, a beginner should be able to see the inspected fields, the exact rule condition, the evidence behind the result, and a corrected counterpart. Whether this is a real gap for a particular team must be validated with users; it is not a claim that AWS tooling is generally inadequate.

## Why it matters

Misconfiguration can contribute to unintended data access, exposure of management services, excessive permissions, or reduced incident visibility. The actual impact depends on the surrounding account, identity, network, data, and compensating controls. A transparent starter auditor can help users learn what to review and when to seek a deeper assessment, while keeping uncertainty visible.

## Prototype goals and measures

Phase 1 sets up a small baseline for a later local prototype:

1. Define five rules with explicit, deterministic conditions and stated limitations.
2. Provide at least one vulnerable and one corrected JSON scenario for each rule (ten scenarios total).
3. Give every scenario an expected result that names its rule IDs and, for findings, severity and field-level evidence.
4. Ensure all sample files are valid JSON and use a shared, documented schema.
5. In a future detector phase, target exact agreement with these ten expected scenarios and require each reported finding to include rule ID, severity, and evidence. This measures fixture behavior only, not real-account accuracy or security coverage.

No live-account access, cloud changes, LLM calls, or detection engine are part of this phase.
