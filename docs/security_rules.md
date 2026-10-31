# Initial security rules

These are deterministic rules for the local teaching fixtures, not a complete AWS security assessment. AWS has account-, organization-, and service-level behavior that is intentionally outside these checks. A finding is a review signal, not proof of exploitability.

## Shared conventions

- Every initial scenario contains one resource. The scanner runs every applicable rule against that resource; rule-specific fixtures use safe baseline values for unrelated checks so their expected result isolates the intended rule. A scenario label (`vulnerable` or `secure`) is descriptive metadata; it never determines whether a rule fires.
- A field that is missing, malformed, or outside a stated supported form is treated as unknown or noncompliant only where the rule explicitly says so.
- Severity is a prototype triage level. Evidence paths point into the simplified resource object.
- Examples use AWS-style concepts and field names, but are sample JSON—not AWS API responses or deployable templates.

## CS-S3-001 — Potential public S3 bucket access

- **Risk:** An unintended public grant can expose bucket objects. Disabled bucket-level Block Public Access controls also remove a protective guardrail.
- **Fields inspected:** `resources[].config.bucket_policy.Statement[]` (`Effect`, `Principal`); `resources[].config.public_access_block.BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets`.
- **Exact detection:** Emit one finding for the resource if either:
  1. any statement has `Effect` exactly `"Allow"` and `Principal` exactly `"*"` or an object whose `AWS` value is exactly `"*"`; or
  2. any of the four Block Public Access fields is not the boolean `true` (including a missing field).
  
  `Action`, `Resource`, and `Condition` do not affect this prototype decision. This intentionally conservative shortcut treats a matching allow principal as a potential public grant; it does not evaluate whether a condition limits access. A missing policy or an empty statement list is not itself a public grant.
- **Vulnerable example:** `s3-public-vulnerable.json` has an allow statement with `Principal: "*"` and all four block settings false.
- **Corrected example:** `s3-public-secure.json` has a specific account principal and all four block settings true.
- **Expected finding:** Vulnerable scenario `s3-public-vulnerable` reports `CS-S3-001`, **High**, with evidence paths `bucket_policy.Statement[0].Principal` and the four false `public_access_block` fields. The corrected scenario has no finding.
- **Severity rationale:** High reflects the potential for unintended access and weakened guardrails; it does not assert that the bucket is reachable or contains sensitive data.
- **False positives and limitations:** Conditions that restrict a wildcard principal are ignored, as are access-point policies, ACLs, account- or organization-level settings, ownership controls, and effective AWS evaluation. A false block setting alone is a guardrail concern, not proof of public access. The four settings are evaluated only at the simplified bucket level.
- **Simple test:** Change `BlockPublicPolicy` from `true` to `false` in the secure fixture; the rule should report a finding even if the policy has no public principal.

## CS-S3-002 — S3 default encryption not recognized

- **Risk:** Explicit default-encryption configuration helps users document and control encryption behavior for new uploads. This check is not an inventory of object encryption.
- **Fields inspected:** `resources[].config.default_encryption.SSEAlgorithm`.
- **Exact detection:** Emit one finding if `default_encryption` or `SSEAlgorithm` is missing, or if `SSEAlgorithm` is not exactly `"AES256"` (SSE-S3) or `"aws:kms"` (SSE-KMS).
- **Vulnerable example:** `s3-encryption-vulnerable.json` has no `default_encryption` object.
- **Corrected example:** `s3-encryption-secure.json` uses `"AES256"`.
- **Expected finding:** Vulnerable scenario `s3-encryption-vulnerable` reports `CS-S3-002`, **Medium**, with evidence `default_encryption.SSEAlgorithm: missing`. The corrected scenario has no finding.
- **Severity rationale:** Medium flags a configuration review gap without claiming that stored data is unencrypted or exposed.
- **False positives and limitations:** AWS S3 applies default encryption to new object uploads, including SSE-S3 by default. This prototype checks only whether one of two explicit algorithm values appears in its input. It does not inspect existing object encryption, bucket policy requirements, KMS key policy or key health, replication, or historical uploads. Other AWS-supported modes, such as DSSE-KMS, are unsupported by this first prototype and will be reported as unsupported rather than invalid in AWS.
- **Simple test:** Replace `"AES256"` in the secure fixture with `"UNSUPPORTED"`; the rule should report the unsupported algorithm.

## CS-NET-001 — Public ingress to a management port

- **Risk:** Public reachability to remote administration or data-service ports can increase exposure to scanning and unauthorized access attempts.
- **Fields inspected:** `resources[].config.ingress[]` (`IpProtocol`, `FromPort`, `ToPort`, `CidrIpv4`, `CidrIpv6`).
- **Exact detection:** For each ingress entry, treat the source as public only when `CidrIpv4` is exactly `"0.0.0.0/0"` or `CidrIpv6` is exactly `"::/0"`. Report when the protocol is `"tcp"`, `"udp"`, or `"-1"` and the rule covers at least one port in `{22, 23, 445, 1433, 3306, 3389, 5432, 5900}`. A protocol of `"-1"` means all ports and triggers without port fields. For `"tcp"` or `"udp"`, both port values must be integers and `FromPort <= risky_port <= ToPort` for at least one listed port. Other protocols and non-exact public CIDR spellings are outside the prototype.
- **Vulnerable example:** `network-ingress-vulnerable.json` allows TCP port 22 from `0.0.0.0/0`.
- **Corrected example:** `network-ingress-secure.json` allows TCP port 22 only from `203.0.113.10/32`.
- **Expected finding:** Vulnerable scenario `network-ingress-vulnerable` reports `CS-NET-001`, **High**, with evidence `ingress[0].CidrIpv4: 0.0.0.0/0` and `ingress[0].FromPort/ToPort: 22`. The corrected scenario has no finding.
- **Severity rationale:** High prioritizes public exposure of selected administrative or data-service ports. The check does not say all public web traffic is unsafe.
- **False positives and limitations:** A port may have application-level controls or be intentionally reachable; context is not evaluated. This check does not combine multiple security groups, network ACLs, routing, firewall rules, load balancers, source security-group references, prefix lists, or IPv6 ranges other than `::/0`. It covers a deliberately small list, not every sensitive port.
- **Simple test:** Change the secure fixture's `CidrIpv4` from `203.0.113.10/32` to `0.0.0.0/0`; the rule should report a finding.

## CS-IAM-001 — Broad IAM action and resource wildcard

- **Risk:** A policy combining wildcard actions with all resources may grant more permissions than intended.
- **Fields inspected:** `resources[].config.policy.Statement[]` (`Effect`, `Action`, `Resource`).
- **Exact detection:** Inspect each statement independently. Emit one finding if a statement has `Effect` exactly `"Allow"`, at least one `Action` equal to `"*"` or matching the exact form `<nonempty-service-name>:*` (for example `"s3:*"` or `"iam:*"`), and at least one `Resource` equal to `"*"`. `Action` and `Resource` may each be a string or a list of strings. Deny statements, partial wildcards such as `"s3:Get*"`, and statements where the action and resource wildcard occur in separate statements do not trigger this rule.
- **Vulnerable example:** `iam-wildcard-vulnerable.json` allows `"Action": "*"` on `"Resource": "*"`.
- **Corrected example:** `iam-wildcard-secure.json` allows only `"s3:GetObject"` on one bucket object ARN.
- **Expected finding:** Vulnerable scenario `iam-wildcard-vulnerable` reports `CS-IAM-001`, **High**, with evidence `policy.Statement[0].Action: *` and `policy.Statement[0].Resource: *`. The corrected scenario has no finding.
- **Severity rationale:** High indicates broad potential permission scope, not that the policy is attached, usable, or exploitable.
- **False positives and limitations:** Wildcard use alone does not establish exploitability or account context. This prototype ignores policy variables, conditions, permissions boundaries, SCPs, session policies, explicit denies, trust relationships, resource policies, service-specific action semantics, and whether the policy is attached to an identity. Narrow resource scoping can materially change impact; this rule intentionally requires a wildcard resource as well.
- **Simple test:** Change the secure fixture's resource to `"*"` and its action to `"s3:*"`; the rule should report a finding.

## CS-CT-001 — CloudTrail trail settings incomplete

- **Risk:** Inadequate trail coverage can limit the event record available for investigation and review.
- **Fields inspected:** `resources[].config.trail.IsLogging`, `IsMultiRegionTrail`, `LogFileValidationEnabled`, `ManagementEventsReadWrite`, and `S3BucketName`.
- **Exact detection:** Emit one finding if the `trail` object is missing, any of `IsLogging`, `IsMultiRegionTrail`, `LogFileValidationEnabled`, or `ManagementEventsReadWrite` is not boolean `true`, or `S3BucketName` is missing, not a string, or empty after trimming. `ManagementEventsReadWrite` is a prototype-only summary flag meaning that read and write management events are selected; it is not an AWS CloudTrail API field.
- **Vulnerable example:** `cloudtrail-vulnerable.json` sets `IsLogging` to false and omits the management-events flag and destination.
- **Corrected example:** `cloudtrail-secure.json` sets all required flags and provides a nonempty destination name.
- **Expected finding:** Vulnerable scenario `cloudtrail-vulnerable` reports `CS-CT-001`, **Medium**, with evidence `trail.IsLogging: false`, `trail.IsMultiRegionTrail: false`, `trail.LogFileValidationEnabled: false`, `trail.ManagementEventsReadWrite: missing`, and `trail.S3BucketName: missing`. The corrected scenario has no finding.
- **Severity rationale:** Medium marks a potential visibility gap while avoiding a claim that no logs exist anywhere.
- **False positives and limitations:** The check does not inspect other trails, organization trails, event selectors in detail, CloudTrail Lake, log delivery health, retention, destination-bucket security, encryption, or all Regions and accounts. AWS CloudTrail has configuration concepts beyond these simplified fields. A trail field can be absent here even when an equivalent control exists elsewhere.
- **Simple test:** Change `LogFileValidationEnabled` from `true` to `false` in the secure fixture; the rule should report a finding.
