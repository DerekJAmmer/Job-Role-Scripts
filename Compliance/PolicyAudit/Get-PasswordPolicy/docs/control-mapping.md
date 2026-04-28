# Control Mapping — Get-PasswordPolicy

## NIST 800-53 Rev 5

| Control | Title | Mapping |
|---------|-------|---------|
| **IA-5** | Authenticator Management | Core control. The script surfaces all password-policy settings (length, complexity, history, age, lockout) that directly govern authenticator quality and lifecycle. |
| **IA-5(1)** | Password-Based Authentication | Sub-control requiring minimum length, complexity, history, and max-age limits — all fields collected by this script. |

## CIS Benchmarks for Windows 11

| CIS Control | Description | Script Field |
|-------------|-------------|--------------|
| **1.1.1** | Enforce password history: 24+ passwords | `HistoryCount` |
| **1.1.2** | Maximum password age: 365 days or fewer (CIS recommends 60) | `MaxAgeDays` |
| **1.1.3** | Minimum password age: 1+ day | `MinAgeDays` |
| **1.1.4** | Minimum password length: 14+ characters | `MinLength` |
| **1.1.5** | Password must meet complexity requirements: Enabled | `ComplexityEnabled` |
| **1.2.1** | Account lockout duration: 15+ minutes | `LockoutDurationMinutes` |
| **1.2.2** | Account lockout threshold: 5 or fewer invalid attempts | `LockoutThreshold` |

## Usage note

Set `-BaselinePath` to a JSON file encoding the CIS or NIST IA-5 thresholds for your environment. Rows with `Status='NonCompliant'` and non-empty `Deltas` identify specific fields that breach the baseline and require remediation.
