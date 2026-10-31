# Dataset guide

## What this dataset is

The Phase 1 dataset is ten small, local JSON fixtures: one vulnerable and one corrected scenario for each of the five rules. Each fixture contains one AWS-style resource in a shared structure. Fields are simplified for beginner readability; the files are not AWS API exports, Terraform plans, or deployment templates. They contain no real account identifiers or credentials. Where a rule-specific fixture contains another field group that a different rule inspects, it includes a safe baseline for that group so the expected finding isolates the intended check.

The labels `vulnerable` and `secure` describe the scenario. A future detector must evaluate the configuration fields and rules; it must not use a label to decide whether to report a finding.

## Shared configuration schema

Every file in `data/configs/` has this shape:

```json
{
  "schema_version": "1.0",
  "scenario_id": "s3-public-vulnerable",
  "label": "vulnerable",
  "resources": [
    {
      "resource_id": "example-bucket",
      "resource_type": "s3_bucket",
      "config": {}
    }
  ]
}
```

`resources[].config` contains fields described in [security_rules.md](security_rules.md). Supported `resource_type` values in these examples are `s3_bucket`, `security_group`, `iam_policy`, and `cloudtrail_trail`. Actual AWS service names and APIs may use different wrappers or capitalization; the individual fields are documented by rule.

## Expected results

`data/expected/results.json` contains one expected result per configuration, keyed by `scenario_id`. Each result includes the scenario label, an `expected_rule_ids` list, and a `findings` list. A finding includes a rule ID, severity, and evidence strings that point to the simplified input fields. Secure scenarios have empty rule-ID and finding lists. A vulnerable scenario's label is not a replacement for the expected rule evaluation.

## Coverage

| Rule ID | Vulnerable fixture | Corrected fixture |
|---|---|---|
| CS-S3-001 | `s3-public-vulnerable.json` | `s3-public-secure.json` |
| CS-S3-002 | `s3-encryption-vulnerable.json` | `s3-encryption-secure.json` |
| CS-NET-001 | `network-ingress-vulnerable.json` | `network-ingress-secure.json` |
| CS-IAM-001 | `iam-wildcard-vulnerable.json` | `iam-wildcard-secure.json` |
| CS-CT-001 | `cloudtrail-vulnerable.json` | `cloudtrail-secure.json` |

This is a minimal fixture set, not a statistically representative dataset. It has no production-derived data, cloud inventory, or labels verified by operational outcomes. Edge cases and invalid-input fixtures can be added in later iterations.

## Adding an example

1. Copy the shared outer structure and use a unique `scenario_id`.
2. Choose `vulnerable` or `secure` as descriptive metadata.
3. Use exactly one resource initially; set its `resource_type` and include the fields that the target rule inspects. For a rule-specific scenario, include safe baseline values for other checks on that resource type to avoid unintended additional findings.
4. Add a matching result object in `data/expected/results.json`, with an explicit `expected_rule_ids` list. Include evidence and severity for each expected finding; use empty lists when no rule should match.
5. Add or update the corresponding example and rule test in [security_rules.md](security_rules.md).
6. Validate JSON syntax and manually compare each config scenario ID/label with its expected result. The Phase 1 files do not include an automated schema or consistency checker.

## Validate and review in PowerShell

Run from the project root. Python 3 is needed only for these standard-library JSON checks; no package installation is required.

Validate every JSON file:

```powershell
Get-ChildItem -Path .\data -Filter *.json -Recurse | ForEach-Object {
    python -m json.tool $_.FullName > $null
    if ($LASTEXITCODE -ne 0) { throw "Invalid JSON: $($_.FullName)" }
}
```

Pretty-print an individual fixture or the expected results:

```powershell
python -m json.tool .\data\configs\s3-public-vulnerable.json
python -m json.tool .\data\expected\results.json
```

List the fixture names:

```powershell
Get-ChildItem .\data\configs -Filter *.json | Select-Object -ExpandProperty Name
```

Review the expected scenario IDs, labels, and rule IDs with PowerShell:

```powershell
$results = Get-Content .\data\expected\results.json -Raw | ConvertFrom-Json
$results.results | Select-Object scenario_id, label, @{Name='expected_rule_ids'; Expression={ $_.expected_rule_ids -join ', ' }} | Format-Table -AutoSize
```

These commands verify JSON parsing and help review contents; they do not prove AWS semantics or perform an automated cross-file schema check.
