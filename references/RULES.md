# Static rule reference

| Rule | Severity | Meaning | Limitation |
|---|---|---|---|
| GHA001 | medium | Workflow does not declare workflow-level `permissions` | Repository defaults may already enforce read-only. |
| GHA002 | high | Workflow/job uses `permissions: write-all` | Broad grants can be intentional in narrow trusted jobs. |
| GHA003 | low | External action not pinned to an immutable full SHA | Tags can be protected; pinning is a defense-in-depth suggestion. |
| GHA004 | high | Untrusted PR/issue/branch content directly interpolated into a run string | Context-sensitive, not proof of exploitability. |
| GHA005 | medium | `${{ secrets.X }}` appears directly in shell run | This is risky interpolation, not proof of leaked values. |
| GHA006 | critical | Under pull_request_target, checks out PR-controlled ref before running shell commands | The actual executed script may be harmless; review trust boundary. |
| GHA007 | low | Checkout persists credentials while effective token permissions include writes | Sometimes needed for trusted pushes. |

The analyzer never makes GitHub API calls, fetches remote code, invokes shell scripts from target workflows, or executes actions. YAML parsing uses PyYAML BaseLoader to preserve the GitHub `on` key.

Primary references:
- https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
- https://docs.github.com/en/actions/concepts/security/script-injections
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax

These rules are conservative, incomplete **heuristics**. Review branch policies, fork permissions, protected environments, secrets scope and action trust separately.
