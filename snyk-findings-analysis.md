# TruffleHog — Snyk Code Findings Analysis

This report triages every result in `results.sarif`, the Snyk Code scan of TruffleHog (Go module `github.com/trufflesecurity/trufflehog/v3`, `go.mod:1`), produced by SnykCode 1.1307.3 under scan identifier `Snyk/Code/2026-09-22T11:48:01Z`. Each verdict is argued from the code at commit `73890ab3c`, not from the scanner's message. The analysis is read-only: it changes no code, and its remediation section is a proposal that has not been run.

## Summary

| Total findings | True positives | False positives | Needs manual review |
| --- | --- | --- | --- |
| 84 | 12 | 71 | 1 |

| Severity | Total | True positives | False positives | Needs manual review |
| --- | --- | --- | --- | --- |
| Critical | 0 | 0 | 0 | 0 |
| High | 9 | 0 | 9 | 0 |
| Medium | 13 | 12 | 1 | 0 |
| Low | 62 | 0 | 61 | 1 |

The 12 true positives are 11 server-side request forgery results, in the ngrok analyzer's pagination (#53–#60) and in Docker registry verification (#61–#63), plus the opt-in Jenkins TLS verification bypass (#65). One result, #27, needs manual review: a complete third-party cloud service-account key is committed as a test fixture, and the repository cannot show whether it has been revoked. Every High-severity result is a false positive, because each flagged input comes from the operator running the scanner.

## How to read this report

### Terms

- **SARIF:** the Static Analysis Results Interchange Format, the OASIS-standard JSON format for static-analysis results; `results.sarif` uses version 2.1.0.
- **Rule ID:** the scanner's identifier for the check that fired, such as `go/Ssrf`.
- **CWE:** an identifier from MITRE's Common Weakness Enumeration, the catalogue of software weakness classes, such as CWE-918.
- **SARIF level:** the severity field each result carries, one of `error`, `warning` or `note`.
- **`/test` suffix:** Snyk's variant of a rule, applied to findings in test code; these rules carry the `InTest` tag in the SARIF.
- **Call site and sink:** where Snyk flags a line on the data path rather than the dangerous call, the entry gives both the flagged call site and the sink, the line that reads the file or sends the request.

### Severity mapping

Severity follows Snyk's own mapping of SARIF levels, documented in [View Snyk Code CLI results](https://docs.snyk.io/developer-tools/snyk-cli/scan-and-maintain-projects-using-the-cli/snyk-cli-for-snyk-code/view-snyk-code-cli-results), section "Severity levels in JSON and SARIF files". Snyk Code does not use Critical, so that bucket is always empty.

| SARIF level | Report severity | Results |
| --- | --- | --- |
| `error` | High | 9: #0, #35–#42 |
| `warning` | Medium | 13: #53–#65 |
| `note` | Low | 62: all others |
| none | Critical | 0 |

Each finding takes its severity from its own `results[i].level`, because SARIF 2.1.0 lets a result's level override the rule's `defaultConfiguration.level`: `go/PT` defaults to `note`, yet results #35–#42 carry `error`. The `priorityScore` property is not a severity input.

### Verdicts and trust model

Most verdicts turn on who controls an input. This report treats the operator who runs `trufflehog` as trusted: the CLI flags and arguments (for example `main.go:101`, `main.go:111` and `main.go:262`), the environment and the paths the operator chooses, and likewise the developer who runs `go generate`. It treats as untrusted all scanned content, which may be attacker-authored and is the input to every detector's `FromData`, and every response from a third-party provider, including any URL a response supplies for a follow-up request. This is the Technical Specification's trust-zone model (§6.4.1.3), in which Zone 4, the providers being asked, is untrusted.

Each entry names the clause that decided its verdict:

- **True positive:** the weakness exists in reachable non-test code, and one of two clauses holds.
  - Taint clause: a party who does not already hold what an exploit would grant can influence the value at the sink, and no control on the path stops it.
  - Configuration clause: the insecure construct serves the security purpose the CWE describes, by default or through a documented option.
- **False positive:** at least one of three clauses holds.
  - Trusted-source clause: the input comes from the trusted operator or developer, from a constant, or from a regex-constrained value that lands in a fixed host.
  - Not-the-weakness clause: the construct is not the weakness the CWE names; for example, no shell parses the arguments, or the hash stores no password.
  - Test-data clause: the code is test code or developer tooling, and the value is synthetic, a placeholder, a negative case or a published test value that no production system accepts.
- **Needs manual review:** the external-evidence clause holds: the verdict depends on evidence outside the repository, such as whether a complete, usable credential that names its service and account has been revoked. The entry names the missing evidence and who can supply it.

`SECURITY.md` and recorded accepted risks are cited as impact context; they never change a verdict. Findings in test code are judged on what the literal or path is, not only on where it sits: a live credential committed in a test would still be a true positive.

### Rules in this scan

| Rule ID | Name | CWE (MITRE title) | Results |
| --- | --- | --- | --- |
| `go/CommandInjection` | Command Injection | CWE-78 OS Command Injection | 1 |
| `go/PT` | Path Traversal | CWE-23 Relative Path Traversal | 9 |
| `go/Ssrf` | Server-Side Request Forgery (SSRF) | CWE-918 Server-Side Request Forgery | 12 |
| `go/TooPermissiveTrustManager` | Improper Certificate Validation - Permissive TrustManager | CWE-295 Improper Certificate Validation | 1 |
| `go/InsecureHash` | Use of Password Hash With Insufficient Computational Effort | CWE-916 Use of Password Hash With Insufficient Computational Effort | 3 |
| `go/PT/test` | Path Traversal | CWE-23 Relative Path Traversal | 10 |
| `go/HardcodedPassword/test` | Use of Hardcoded Passwords | CWE-798 Use of Hard-coded Credentials; CWE-259 Use of Hard-coded Password | 24 |
| `go/NoHardcodedCredentials/test` | Use of Hardcoded Credentials | CWE-798 Use of Hard-coded Credentials | 20 |
| `go/HardcodedNonCryptoSecret/test` | Hardcoded Non-Cryptographic Secret | CWE-547 Use of Hard-coded, Security-relevant Constants | 3 |
| `python/HardcodedNonCryptoSecret/test` | Hardcoded Non-Cryptographic Secret | CWE-547 Use of Hard-coded, Security-relevant Constants | 1 |

Names are the SARIF `shortDescription` of each rule; the SARIF also carries Snyk's full rule text in `help.markdown`. Snyk's public rule tables, [Snyk Code Go rules](https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-code/snyk-code-security-rules/go-rules) and [Snyk Code Python rules](https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-code/snyk-code-security-rules/python-rules), list the same rules by name and CWE but have no page per rule ID and no `/test` variants.

## Critical

There are no Critical findings: Snyk Code does not assign the Critical severity, so no SARIF level maps to it.

## High

### High — True positives

None.

### High — False positives

#### Result #0 — go/CommandInjection — main.go:361

- **Rule:** `go/CommandInjection` — Command Injection, CWE-78
- **Severity:** High (SARIF level `error`)
- **Location:** `main.go:361` (sink; the flow starts at `main.go:356`)
- **Summary:** When TruffleHog starts on a terminal with no subcommand, or with only `analyze`, it runs the interactive wizard and then re-executes its own binary with the arguments the wizard returns. Snyk reads that re-execution as a shell command built from CLI input.
- **Verdict:** False positive
- **Reasoning:** The executed binary is `exec.LookPath(os.Args[0])` (`main.go:356`), and its arguments are what `tui.Run(os.Args[1:])` returns (`main.go:346`) after `expandTilde` (`main.go:302-319`, called at `main.go:354`). The branch runs inside `init()` only when stdout is a terminal and no subcommand, or only `analyze`, was given (`main.go:345`). The sink at `main.go:360-361` hands each element to `execve` as a separate argument, and no shell parses it; the comment at `main.go:351-353` records that shell invocation was removed:

  ```go
  execArgs := append([]string{binary}, args...)
  _ = syscall.Exec(binary, execArgs, append(os.Environ(), "TUI_PARENT=true"))
  ```

  Only the operator controls `argv[0]`, `PATH` and the wizard input, and the operator can already run any program, so the CWE-78 premise of untrusted data reaching a shell command does not hold. Criterion: false positive, trusted-source and not-the-weakness clauses.
- **SARIF reference:** `runs[0].results[0]`, identity `e1e44413-9392-44bb-ac52-181a39169fe3`

Results #35–#42 follow one value: the repository URI the operator passes to `trufflehog git` (`main.go:101`), which reaches `PrepareRepo` through `Source.Init` and `prepareRepoSinceCommit` (`pkg/sources/git/git.go:194-195`, `pkg/sources/git/git.go:1482`) and is normalised by `normalizeFileURI` (`pkg/sources/git/git.go:445-470`). Snyk calls it input from "the request URL", but it is the path of a local `file://` repository and no HTTP request is involved; the binary's only HTTP listener is the opt-in `--profile` pprof server on port 18066 (`main.go:53`, `main.go:496-508`), which handles no scan input.

#### Result #35 — go/PT — pkg/sources/git/git.go:512

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:512` (call site; file read at `pkg/sources/git/git.go:1614`)
- **Summary:** `CloneRepo` calls `executeClone` on this line. Snyk's flow for the local repository path passes through it and ends where `PrepareRepo` reads the source repository's `commondir` file.
- **Verdict:** False positive
- **Reasoning:** The flagged line `pkg/sources/git/git.go:512` reads no file; it clones into a directory that `createClonePath` has just made (`pkg/sources/git/git.go:507`, `pkg/sources/git/git.go:587-614`). The read happens at `pkg/sources/git/git.go:1614`. The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[35]`, identity `ab90fda9-02af-4f4d-a1ce-912936fff971`

#### Result #36 — go/PT — pkg/sources/git/git.go:757

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:757` (call site; file read at `pkg/sources/git/git.go:1614`)
- **Summary:** `CloneRepoUsingToken` forwards its URL to `CloneRepo` on this line. Snyk's flow for the local repository path runs through the call on its way to the `commondir` read in `PrepareRepo`.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git.go:755-757` is a wrapper for authenticated remote clones (called at `pkg/sources/git/git.go:318`); the local path that reaches the read at `pkg/sources/git/git.go:1614` goes through `CloneRepo` directly (`pkg/sources/git/git.go:1581`). The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[36]`, identity `098895a0-074b-49b9-9cb4-78f5844c2f3b`

#### Result #37 — go/PT — pkg/sources/git/git.go:762

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:762` (call site; file read at `pkg/sources/git/git.go:1614`)
- **Summary:** `CloneRepoUsingUnauthenticated` forwards its URL to `CloneRepo` on this line. Snyk's flow for the local repository path runs through the call on its way to the `commondir` read in `PrepareRepo`.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git.go:761-762` is a wrapper for unauthenticated remote clones (called at `pkg/sources/git/git.go:322`); the local path that reaches the read at `pkg/sources/git/git.go:1614` goes through `CloneRepo` directly (`pkg/sources/git/git.go:1581`). The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[37]`, identity `473437e3-b6a9-4a76-b4ab-a4773d4b5195`

#### Result #38 — go/PT — pkg/sources/git/git.go:768

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:768` (call site; file read at `pkg/sources/git/git.go:1614`)
- **Summary:** The AWS CodeCommit branch of `CloneRepoUsingSSH` forwards its URL to `CloneRepo` on this line. Snyk's flow for the local repository path runs through the call on its way to the `commondir` read in `PrepareRepo`.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git.go:766-768` serves SSH clones of CodeCommit URLs (called at `pkg/sources/git/git.go:326`); the local path that reaches the read at `pkg/sources/git/git.go:1614` goes through `CloneRepo` directly (`pkg/sources/git/git.go:1581`). The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[38]`, identity `b90ec8d4-4a67-487b-aa81-0eacba0227e3`

#### Result #39 — go/PT — pkg/sources/git/git.go:772

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:772` (call site; file read at `pkg/sources/git/git.go:1614`)
- **Summary:** The default branch of `CloneRepoUsingSSH` forwards its URL to `CloneRepo` on this line. Snyk's flow for the local repository path runs through the call on its way to the `commondir` read in `PrepareRepo`.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git.go:771-772` serves SSH clones as user `git` (called at `pkg/sources/git/git.go:326`); the local path that reaches the read at `pkg/sources/git/git.go:1614` goes through `CloneRepo` directly (`pkg/sources/git/git.go:1581`). The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[39]`, identity `17aed0ac-4155-4345-8585-bb5e09e60311`

#### Result #40 — go/PT — pkg/sources/git/git.go:805

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:805`
- **Summary:** `resolveGitDir` reads the `.git` entry of the operator's repository when it is a file, as in a git worktree, and follows its `gitdir:` pointer to the real git directory.
- **Verdict:** False positive
- **Reasoning:** `os.ReadFile` at `pkg/sources/git/git.go:805` reads `.git` under the repository path given to `resolveGitDir` (`pkg/sources/git/git.go:791-792`, called at `pkg/sources/git/git.go:1592`), and `pkg/sources/git/git.go:810-827` turns its `gitdir:` line into a cleaned path. The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[40]`, identity `843181c9-010c-4648-8d55-17da1e481f8c`

#### Result #41 — go/PT — pkg/sources/git/git.go:1600

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:1600`
- **Summary:** `PrepareRepo` reads the index file of the operator's original repository so the temporary clone can see staged changes.
- **Verdict:** False positive
- **Reasoning:** `os.ReadFile` at `pkg/sources/git/git.go:1600` reads `index` from the git directory `resolveGitDir` returned (`pkg/sources/git/git.go:1592-1597`), and `pkg/sources/git/git.go:1604` writes it into the clone only. The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[41]`, identity `1363d6e8-7ec1-4bf6-b100-16c29e58da5c`

#### Result #42 — go/PT — pkg/sources/git/git.go:1614

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** High (SARIF level `error`)
- **Location:** `pkg/sources/git/git.go:1614`
- **Summary:** `PrepareRepo` reads the `commondir` file of the operator's original git directory to find the shared object store of a worktree.
- **Verdict:** False positive
- **Reasoning:** `os.ReadFile` at `pkg/sources/git/git.go:1614` reads `commondir` from the git directory `resolveGitDir` returned (`pkg/sources/git/git.go:1592`); the result only sets the alternates file of the temporary clone (`pkg/sources/git/git.go:1619-1623`). The path is the operator's `trufflehog git` argument (`main.go:101`), carried through `PrepareRepo` (`pkg/sources/git/git.go:1558`) to `uriPath` (`pkg/sources/git/git.go:1589`). An untrusted `file://` repository is first cloned into a fresh temporary directory (`pkg/sources/git/git.go:1572-1584`) unless the operator passes `--trust-local-git-config` (`main.go:111`), and `TestGitConfigSecurityIsolation` covers that isolation (`pkg/sources/git/git_test.go:1015`). Residual: a `.git` file in an untrusted checkout can point these reads at another git directory on the host, as git itself would, but the reads run with the operator's permissions and feed only the operator's scan. Criterion: false positive, trusted-source clause.
- **SARIF reference:** `runs[0].results[42]`, identity `89cee726-4673-453d-a0a5-b0c68c02e3ca`

### High — Needs manual review

None.

## Medium

### Medium — True positives

Results #53–#60 are one flow in the ngrok analyzer, which runs when the operator invokes `trufflehog analyze` on an ngrok API key (`pkg/analyzer/analyzers/ngrok/ngrok.go:36-72`). Snyk names the source "reader"; that is the constant `{}` POST body (`pkg/analyzer/analyzers/ngrok/requests.go:242`), and the value that matters is `next_page_uri`, which each JSON response supplies (`pkg/analyzer/analyzers/ngrok/models.go:70`).

#### Result #53 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:92

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:92` (call site; request built at `pkg/analyzer/analyzers/ngrok/requests.go:244`)
- **Summary:** `populateEndpoints` pages through the ngrok endpoints list by calling `fetchResources` in a loop. After the first page, the URL it passes is the one the previous ngrok response supplied.
- **Verdict:** True positive
- **Reasoning:** The loop starts at a constant URL built from `ngrokAPIBaseURL` (`pkg/analyzer/analyzers/ngrok/requests.go:14`, `pkg/analyzer/analyzers/ngrok/requests.go:89`), but after each page `pkg/analyzer/analyzers/ngrok/requests.go:97` replaces it with the value from the previous JSON response:

  ```go
  url = res.NextPageURI
  ```

  The flagged call at `pkg/analyzer/analyzers/ngrok/requests.go:92` passes that URL on. No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[53]`, identity `a979a639-84eb-43f0-80df-e77e12cdfee6`

#### Result #54 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:109

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:109` (call site; request built at `pkg/analyzer/analyzers/ngrok/requests.go:244`)
- **Summary:** `populateAPIKeys` pages through the ngrok API keys list by calling `fetchResources` in a loop. After the first page, the URL it passes is the one the previous ngrok response supplied.
- **Verdict:** True positive
- **Reasoning:** The loop starts at a constant URL built from `ngrokAPIBaseURL` (`pkg/analyzer/analyzers/ngrok/requests.go:14`), but `pkg/analyzer/analyzers/ngrok/requests.go:114` replaces it with `res.NextPageURI` from the previous JSON response, and the flagged call at `pkg/analyzer/analyzers/ngrok/requests.go:109` passes it on. No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[54]`, identity `438f896b-3037-4221-b9dc-403d12d7cd0a`

#### Result #55 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:126

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:126` (call site; request built at `pkg/analyzer/analyzers/ngrok/requests.go:244`)
- **Summary:** `populateSSHCredentials` pages through the ngrok SSH credentials list by calling `fetchResources` in a loop. After the first page, the URL it passes is the one the previous ngrok response supplied.
- **Verdict:** True positive
- **Reasoning:** The loop starts at a constant URL built from `ngrokAPIBaseURL` (`pkg/analyzer/analyzers/ngrok/requests.go:14`), but `pkg/analyzer/analyzers/ngrok/requests.go:131` replaces it with `res.NextPageURI` from the previous JSON response, and the flagged call at `pkg/analyzer/analyzers/ngrok/requests.go:126` passes it on. No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[55]`, identity `80989f83-c38c-4744-9705-7447a80e4c12`

#### Result #56 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:143

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:143` (call site; request built at `pkg/analyzer/analyzers/ngrok/requests.go:244`)
- **Summary:** `populateAuthtokens` pages through the ngrok authtokens list by calling `fetchResources` in a loop. After the first page, the URL it passes is the one the previous ngrok response supplied.
- **Verdict:** True positive
- **Reasoning:** The loop starts at a constant URL built from `ngrokAPIBaseURL` (`pkg/analyzer/analyzers/ngrok/requests.go:14`), but `pkg/analyzer/analyzers/ngrok/requests.go:148` replaces it with `res.NextPageURI` from the previous JSON response, and the flagged call at `pkg/analyzer/analyzers/ngrok/requests.go:143` passes it on. No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[56]`, identity `315b7e69-b984-4b65-bde6-7b8d3eab2ecb`

#### Result #57 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:160

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:160` (call site; request built at `pkg/analyzer/analyzers/ngrok/requests.go:244`)
- **Summary:** `populateDomains` pages through the ngrok reserved domains list by calling `fetchResources` in a loop. After the first page, the URL it passes is the one the previous ngrok response supplied.
- **Verdict:** True positive
- **Reasoning:** The loop starts at a constant URL built from `ngrokAPIBaseURL` (`pkg/analyzer/analyzers/ngrok/requests.go:14`), but `pkg/analyzer/analyzers/ngrok/requests.go:165` replaces it with `res.NextPageURI` from the previous JSON response, and the flagged call at `pkg/analyzer/analyzers/ngrok/requests.go:160` passes it on. No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[57]`, identity `987eef4d-9c1a-41fc-9aab-57c35fb22001`

#### Result #58 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:177

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:177` (call site; request built at `pkg/analyzer/analyzers/ngrok/requests.go:244`)
- **Summary:** `populateBotUsers` pages through the ngrok bot users list by calling `fetchResources` in a loop. After the first page, the URL it passes is the one the previous ngrok response supplied.
- **Verdict:** True positive
- **Reasoning:** The loop starts at a constant URL built from `ngrokAPIBaseURL` (`pkg/analyzer/analyzers/ngrok/requests.go:14`), but `pkg/analyzer/analyzers/ngrok/requests.go:182` replaces it with `res.NextPageURI` from the previous JSON response, and the flagged call at `pkg/analyzer/analyzers/ngrok/requests.go:177` passes it on. No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[58]`, identity `56ab98bc-0c1b-4acc-bf38-3d574c4a3ad4`

#### Result #59 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:192

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:192` (call site; request built at `pkg/analyzer/analyzers/ngrok/requests.go:244`)
- **Summary:** `fetchResources` passes the URL it was given to `makeAPIRequest` for a GET. For every page after the first, that URL came from the previous ngrok response.
- **Verdict:** True positive
- **Reasoning:** The flagged call at `pkg/analyzer/analyzers/ngrok/requests.go:192` receives the URL from all six pagination loops, each of which assigns `res.NextPageURI` from the previous response before the next call (for example `pkg/analyzer/analyzers/ngrok/requests.go:97` and `pkg/analyzer/analyzers/ngrok/requests.go:182`). No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[59]`, identity `a58a9a58-177c-4d7b-abb1-fb72b2f26889`

#### Result #60 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:244

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/analyzer/analyzers/ngrok/requests.go:244`
- **Summary:** `makeAPIRequest` builds the HTTP request from whatever URL it receives and adds the analysed key as a Bearer token. For paginated calls that URL is response-supplied.
- **Verdict:** True positive
- **Reasoning:** The sink `http.NewRequest(method, url, reqBody)` at `pkg/analyzer/analyzers/ngrok/requests.go:244` takes the URL that `fetchResources` passes (`pkg/analyzer/analyzers/ngrok/requests.go:192`), which after the first page is `res.NextPageURI` from the previous response (`pkg/analyzer/analyzers/ngrok/requests.go:97`, `pkg/analyzer/analyzers/ngrok/requests.go:261`). No scheme, host, same-origin or local-address check applies before the request (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`, `pkg/analyzer/analyzers/ngrok/requests.go:239-251`), and each request carries the analysed key as a Bearer token (`pkg/analyzer/analyzers/ngrok/requests.go:248`); the client from `analyzers.NewAnalyzeClient` (`pkg/analyzer/analyzers/ngrok/ngrok.go:72`, `pkg/analyzer/analyzers/client.go:35-51`) passes GET requests through unchecked (`pkg/analyzer/analyzers/client.go:124-134`). Provider responses are untrusted, so whoever controls a response can send the next request, key attached, to any host the scanner can reach, including loopback and cloud-metadata addresses. Likelihood is low, since that needs control of the TLS-authenticated api.ngrok.com response and the operator must be analysing an ngrok key; the SSRF is blind, which `SECURITY.md:4` and `SECURITY.md:11-14` class as hardening, while sending the key to an attacker endpoint is CVE-class under `SECURITY.md:7-8`. That context sets impact, not the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[60]`, identity `36b80789-be27-4afb-a6a9-379b663fee3c`

Results #61–#63 are the Docker detector's verification requests. Snyk names the source "reader"; it is the JSON decoder over text matched in scanned content (`pkg/detectors/docker/docker_auth_config.go:89`), and `keyPat` accepts any registry host with an optional `http://` or `https://` prefix (`pkg/detectors/docker/docker_auth_config.go:51`), so the registry is whatever the content's author wrote.

#### Result #61 — go/Ssrf — pkg/detectors/docker/docker_auth_config.go:133

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/detectors/docker/docker_auth_config.go:133` (call site; request built at `pkg/detectors/docker/docker_auth_config.go:155`)
- **Summary:** `FromData` hands each registry named in a matched Docker `auths` block to `verifyMatch` when verification is on. The registry comes from the scanned text, not from the operator.
- **Verdict:** True positive
- **Reasoning:** The flagged call at `pkg/detectors/docker/docker_auth_config.go:133` passes the content-supplied registry and Basic credential to `verifyMatch`, which requests `/v2/` on that host (`pkg/detectors/docker/docker_auth_config.go:147-165`) and, after a 401, the realm the registry names (`pkg/detectors/docker/docker_auth_config.go:186-218`). It uses the client chosen at `pkg/detectors/docker/docker_auth_config.go:127-131`:

  ```go
  client = common.SaneHttpClient()
  ```

  The only filter on the host is a five-entry list of example registries (`pkg/detectors/docker/docker_auth_config.go:61-67`, `pkg/detectors/docker/docker_auth_config.go:104`). Missing control: the fallback client `common.SaneHttpClient()` (`pkg/detectors/docker/docker_auth_config.go:127-131`, `pkg/common/http.go:259-264`) blocks no local address and follows redirects, and the package's `DetectorHttpClientWithNoLocalAddresses` (`pkg/detectors/http.go:40-45`) is not used, so a content author can make the scanning host send GETs to loopback, link-local metadata or other internal addresses. The SSRF is blind, because the response is reduced to a verified flag or an error (`pkg/detectors/docker/docker_auth_config.go:175-239`), and the credential sent is the one the same content supplied; `SECURITY.md:11-14` classes this as hardening, and `--no-verification` (`main.go:60`) disables the path. Neither changes the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[61]`, identity `9a985233-fbdd-4ad0-829b-36e1f89215a7`

#### Result #62 — go/Ssrf — pkg/detectors/docker/docker_auth_config.go:155

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/detectors/docker/docker_auth_config.go:155`
- **Summary:** `verifyMatch` builds the first verification request, a GET to the registry's `/v2/` endpoint. The registry host is the one written in the scanned content.
- **Verdict:** True positive
- **Reasoning:** The request at `pkg/detectors/docker/docker_auth_config.go:155` targets `https://` plus the content-supplied registry plus `/v2/`, or keeps an explicit `http://` prefix (`pkg/detectors/docker/docker_auth_config.go:147-152`), and carries the matched Basic credential (`pkg/detectors/docker/docker_auth_config.go:160`). The only filter on the host is a five-entry list of example registries (`pkg/detectors/docker/docker_auth_config.go:61-67`, `pkg/detectors/docker/docker_auth_config.go:104`). Missing control: the fallback client `common.SaneHttpClient()` (`pkg/detectors/docker/docker_auth_config.go:127-131`, `pkg/common/http.go:259-264`) blocks no local address and follows redirects, and the package's `DetectorHttpClientWithNoLocalAddresses` (`pkg/detectors/http.go:40-45`) is not used, so a content author can make the scanning host send GETs to loopback, link-local metadata or other internal addresses. The SSRF is blind, because the response is reduced to a verified flag or an error (`pkg/detectors/docker/docker_auth_config.go:175-239`), and the credential sent is the one the same content supplied; `SECURITY.md:11-14` classes this as hardening, and `--no-verification` (`main.go:60`) disables the path. Neither changes the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[62]`, identity `123abb87-3b21-4705-a03d-1e66a3a112d2`

#### Result #63 — go/Ssrf — pkg/detectors/docker/docker_auth_config.go:204

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/detectors/docker/docker_auth_config.go:204`
- **Summary:** After a 401, `verifyMatch` builds a second request to the token realm named in the registry's `Www-Authenticate` header. Both the registry and its response are outside the operator's control.
- **Verdict:** True positive
- **Reasoning:** The request at `pkg/detectors/docker/docker_auth_config.go:204` targets the realm parsed from the response header (`pkg/detectors/docker/docker_auth_config.go:186-199`), so a registry run by the content author can point this second request anywhere, and `pkg/detectors/docker/docker_auth_config.go:209` attaches the same Basic credential. The only filter on the host is a five-entry list of example registries (`pkg/detectors/docker/docker_auth_config.go:61-67`, `pkg/detectors/docker/docker_auth_config.go:104`). Missing control: the fallback client `common.SaneHttpClient()` (`pkg/detectors/docker/docker_auth_config.go:127-131`, `pkg/common/http.go:259-264`) blocks no local address and follows redirects, and the package's `DetectorHttpClientWithNoLocalAddresses` (`pkg/detectors/http.go:40-45`) is not used, so a content author can make the scanning host send GETs to loopback, link-local metadata or other internal addresses. The SSRF is blind, because the response is reduced to a verified flag or an error (`pkg/detectors/docker/docker_auth_config.go:175-239`), and the credential sent is the one the same content supplied; `SECURITY.md:11-14` classes this as hardening, and `--no-verification` (`main.go:60`) disables the path. Neither changes the verdict. Criterion: true positive, taint clause.
- **SARIF reference:** `runs[0].results[63]`, identity `d4af6b5c-8b5e-4444-9964-1ae13a1ffb35`

#### Result #65 — go/TooPermissiveTrustManager — pkg/roundtripper/roundtripper.go:126

- **Rule:** `go/TooPermissiveTrustManager` — Improper Certificate Validation - Permissive TrustManager, CWE-295
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/roundtripper/roundtripper.go:126`
- **Summary:** `WithInsecureTLS` gives the round tripper a transport whose TLS configuration accepts any certificate and any host name.
- **Verdict:** True positive
- **Reasoning:** The construct at `pkg/roundtripper/roundtripper.go:126`, inside `WithInsecureTLS` (`pkg/roundtripper/roundtripper.go:122-128`), disables certificate verification:

  ```go
  TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  ```

  Its only caller is the Jenkins source, which adds it when the connection asks for it (`pkg/sources/jenkins/jenkins.go:89-92`). The switch is the default-off flag `--insecure-skip-verify-tls`, also settable as `JENKINS_INSECURE_SKIP_VERIFY_TLS` (`main.go:262`), and is wired into the connection at `pkg/engine/jenkins.go:64`. Once it is on, anyone on the network path to Jenkins can present any certificate and read the Basic credentials the source sends (`pkg/sources/jenkins/jenkins.go:162`), which is exactly CWE-295. The option is opt-in and documented, and the Technical Specification records it as an accepted risk (§6.4.5.4); both limit exposure without removing the weakness. Criterion: true positive, configuration clause.
- **SARIF reference:** `runs[0].results[65]`, identity `e403920b-1fbb-4545-8bec-597558c61f41`

### Medium — False positives

#### Result #64 — go/Ssrf — pkg/detectors/pusherchannelkey/pusherchannelkey.go:136

- **Rule:** `go/Ssrf` — Server-Side Request Forgery (SSRF), CWE-918
- **Severity:** Medium (SARIF level `warning`)
- **Location:** `pkg/detectors/pusherchannelkey/pusherchannelkey.go:136`
- **Summary:** The Pusher detector verifies a candidate key by posting a fixed test event to Pusher's API with a signed query string. Snyk names the constant request body as the source.
- **Verdict:** False positive
- **Reasoning:** The request at `pkg/detectors/pusherchannelkey/pusherchannelkey.go:136` goes to the fixed host `https://api-ap1.pusher.com/apps/` (`pkg/detectors/pusherchannelkey/pusherchannelkey.go:134`). The app ID and key interpolated into the path and query come from scanned content but must match `[0-9]{7}` and `[a-z0-9]{20}` (`pkg/detectors/pusherchannelkey/pusherchannelkey.go:35-36`), and the signature is hex-encoded (`pkg/detectors/pusherchannelkey/pusherchannelkey.go:132`), so no value can change the scheme, host or port. The body Snyk tracks is a constant string (`pkg/detectors/pusherchannelkey/pusherchannelkey.go:115-116`). Criterion: false positive, trusted-source clause: constant and regex-constrained values land in a fixed host.
- **SARIF reference:** `runs[0].results[64]`, identity `4b7e6d28-0d53-42fe-9a93-990bddca9cc0`

### Medium — Needs manual review

None.

## Low

### Low — True positives

None.

### Low — False positives

Results #33 and #43–#52 are path-traversal results in developer tooling and tests. In each, the path comes from the developer or from the test itself.

#### Result #33 — go/PT — pkg/analyzer/generate_permissions/generate_permissions.go:110

- **Rule:** `go/PT` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/analyzer/generate_permissions/generate_permissions.go:110`
- **Summary:** The permissions code generator opens the YAML file named by its first command-line argument.
- **Verdict:** False positive
- **Reasoning:** `pkg/analyzer/generate_permissions/generate_permissions.go:110` calls `os.Open(os.Args[1])` in a `package main` program (`pkg/analyzer/generate_permissions/generate_permissions.go:1`) that is not linked into the `trufflehog` binary. It runs only through fixed `//go:generate` directives such as `pkg/analyzer/analyzers/sendgrid/sendgrid.go:1`, which pass a checked-in `permissions.yaml`, so the path comes from the developer running `go generate`, who can already read any file the generator could open. Criterion: false positive, trusted-source and test-data clauses.
- **SARIF reference:** `runs[0].results[33]`, identity `be040c65-4f32-4ff8-a5d2-6f4a1645cab6`

Results #43–#52 flag cleanup calls in `pkg/sources/git/git_test.go`. Snyk starts each flow at `pkg/sources/git/git.go:1589`, but every path removed is one the test itself created from a hard-coded test input.

#### Result #43 — go/PT/test — pkg/sources/git/git_test.go:122

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:122`
- **Summary:** `TestCreateClonePath` removes the temporary directory it has just created.
- **Verdict:** False positive
- **Reasoning:** The deferred `os.RemoveAll` at `pkg/sources/git/git_test.go:122` deletes the path `createClonePath` returned for a hard-coded GitHub URL and an empty clone path (`pkg/sources/git/git_test.go:120`), which is a fresh directory from `cleantemp.MkdirTemp` (`pkg/sources/git/git.go:587-594`). No outside input names the path. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[43]`, identity `b8866291-7cdb-4e7d-a0a2-5af0d44bc187`

#### Result #44 — go/PT/test — pkg/sources/git/git_test.go:139

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:139`
- **Summary:** The uniqueness subtest of `TestCreateClonePath` removes the first of two temporary directories it created.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git_test.go:139` deletes the path returned at `pkg/sources/git/git_test.go:137` for a hard-coded URL and an empty clone path, a fresh temporary directory (`pkg/sources/git/git.go:587-594`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[44]`, identity `aad337e8-a1f2-461f-90e2-1d9fda29c0ec`

#### Result #45 — go/PT/test — pkg/sources/git/git_test.go:143

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:143`
- **Summary:** The same subtest removes the second temporary directory it created.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git_test.go:143` deletes the path returned at `pkg/sources/git/git_test.go:141`, again a fresh temporary directory from `createClonePath` (`pkg/sources/git/git.go:587-594`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[45]`, identity `93da4de0-c329-48c8-9be5-22dd5a85e5a0`

#### Result #46 — go/PT/test — pkg/sources/git/git_test.go:316

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:316`
- **Summary:** `TestCloneRepo_ConcurrentSameBasename` removes each clone after checking where it landed.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git_test.go:316` deletes a clone that `CloneRepo` made under the test's own `t.TempDir()` clone path (`pkg/sources/git/git_test.go:280`), from `file://` repositories the test built (`pkg/sources/git/git_test.go:285-292`); the comment at `pkg/sources/git/git_test.go:315` notes that it mirrors caller cleanup. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[46]`, identity `91621f4b-a032-46eb-adc1-21deb7423a3f`

#### Result #47 — go/PT/test — pkg/sources/git/git_test.go:1215

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:1215`
- **Summary:** `TestPrepareRepoWithWorktree` removes the directory `PrepareRepo` produced for a test worktree.
- **Verdict:** False positive
- **Reasoning:** The deferred removal at `pkg/sources/git/git_test.go:1215` deletes the path `PrepareRepo` returned for `file://` plus the test's own worktree path (`pkg/sources/git/git_test.go:1208-1209`), a temporary clone. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[47]`, identity `1218e75f-d7b7-4b8e-b6be-946640c2db78`

#### Result #48 — go/PT/test — pkg/sources/git/git_test.go:1348

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:1348`
- **Summary:** `TestPrepareRepoWithNormalization` removes the clone `PrepareRepo` made for an absolute `file://` URI.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git_test.go:1348` runs only under the guard `path != repoPath` (`pkg/sources/git/git_test.go:1347`), so it deletes the temporary clone and never the test repository; the URIs are `file://` plus the test repository path (`pkg/sources/git/git_test.go:1321-1330`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[48]`, identity `205489e3-12df-4a29-b30e-294971c30600`

#### Result #49 — go/PT/test — pkg/sources/git/git_test.go:1385

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:1385`
- **Summary:** The relative-URI cases of `TestPrepareRepoWithNormalization` remove the clone made for `file://.`.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git_test.go:1385` runs under the same `path != repoPath` guard (`pkg/sources/git/git_test.go:1384`), for the fixed URI `file://.` (`pkg/sources/git/git_test.go:1358-1366`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[49]`, identity `cc4a4857-ccb8-45d7-978b-dda808e4d9b6`

#### Result #50 — go/PT/test — pkg/sources/git/git_test.go:1450

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:1450`
- **Summary:** `TestPrepareRepoWithNormalizationBare` removes the clone `PrepareRepo` made from a test bare repository.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git_test.go:1450` runs only under the guard `path != bareRepoPath` (`pkg/sources/git/git_test.go:1449`), and the bare repository lives in the test's own `t.TempDir()` (`pkg/sources/git/git_test.go:1392`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[50]`, identity `fc07f77a-3e55-457f-b017-6b1066adf6dc`

#### Result #51 — go/PT/test — pkg/sources/git/git_test.go:1499

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:1499`
- **Summary:** A later case of `TestPrepareRepoWithNormalizationBare` removes its clone the same way.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/git/git_test.go:1499` runs under the guard `path != bareRepoPath` (`pkg/sources/git/git_test.go:1498`) for the same test-owned bare repository (`pkg/sources/git/git_test.go:1392`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[51]`, identity `6d8c31e6-c43d-4be3-8e0e-11ee11550ea4`

#### Result #52 — go/PT/test — pkg/sources/git/git_test.go:1070

- **Rule:** `go/PT/test` — Path Traversal, CWE-23
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/git/git_test.go:1070`
- **Summary:** `TestGitConfigSecurityIsolation` deletes the probe file its planted git alias may have created.
- **Verdict:** False positive
- **Reasoning:** `os.Remove` at `pkg/sources/git/git_test.go:1070` deletes `malicious_alias.txt` under the prepared path (`pkg/sources/git/git_test.go:1038`), after the test has checked whether the file exists (`pkg/sources/git/git_test.go:1065-1069`); the prepared path comes from `PrepareRepo` on the test's own repository (`pkg/sources/git/git_test.go:1032-1033`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[52]`, identity `91ce2dfd-488c-4f9f-953b-d3d58a8b9d89`

Results #10–#12 flag SHA-1 and MD5. CWE-916 concerns hashing passwords for storage with too little computational effort, and none of these hashes stores a password.

#### Result #10 — go/InsecureHash — pkg/detectors/privatekey/fingerprint.go:48

- **Rule:** `go/InsecureHash` — Use of Password Hash With Insufficient Computational Effort, CWE-916
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/privatekey/fingerprint.go:48`
- **Summary:** `fingerprintPublicKey` computes the SHA-1 of a DER-encoded public key and returns it as hex.
- **Verdict:** False positive
- **Reasoning:** The input to `sha1.Sum` at `pkg/detectors/privatekey/fingerprint.go:48` is the public half of a found key, marshalled at `pkg/detectors/privatekey/fingerprint.go:43`. The fingerprint is a lookup identifier: the detector derives it at `pkg/detectors/privatekey/privatekey.go:101` and uses it to query `keychecker.trufflesecurity.com` (`pkg/detectors/privatekey/privatekey.go:223`). No password is hashed or stored. Criterion: false positive, not-the-weakness clause.
- **SARIF reference:** `runs[0].results[10]`, identity `2a681d2e-1e89-43b8-be73-975349d1f5c8`

#### Result #11 — go/InsecureHash — pkg/detectors/pusherchannelkey/pusherchannelkey.go:117

- **Rule:** `go/InsecureHash` — Use of Password Hash With Insufficient Computational Effort, CWE-916
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/pusherchannelkey/pusherchannelkey.go:117`
- **Summary:** The Pusher detector computes the MD5 of its constant request body for the `body_md5` query parameter.
- **Verdict:** False positive
- **Reasoning:** `md5.New()` at `pkg/detectors/pusherchannelkey/pusherchannelkey.go:117` hashes the constant payload from `pkg/detectors/pusherchannelkey/pusherchannelkey.go:115`, and the hex digest becomes `body_md5` (`pkg/detectors/pusherchannelkey/pusherchannelkey.go:119-126`), a field Pusher's request-signing scheme requires. The signature itself is HMAC-SHA256 (`pkg/detectors/pusherchannelkey/pusherchannelkey.go:97-101`). Nothing secret is hashed and no password is stored. Criterion: false positive, not-the-weakness clause.
- **SARIF reference:** `runs[0].results[11]`, identity `f26a3fb8-95ad-415e-9386-98fb28f35852`

#### Result #12 — go/InsecureHash — pkg/engine/engine.go:1361

- **Rule:** `go/InsecureHash` — Use of Password Hash With Insufficient Computational Effort, CWE-916
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/engine/engine.go:1361`
- **Summary:** The engine derives an MD5 key for its in-memory result dedupe cache.
- **Verdict:** False positive
- **Reasoning:** `md5.Sum` at `pkg/engine/engine.go:1361` hashes the detector name, type, raw result and source metadata into a cache key that is only looked up and added in memory (`pkg/engine/engine.go:1362-1367`); the comment at `pkg/engine/engine.go:1354-1355` gives the reason, keeping the cache small. The digest is never stored as a password verifier. Criterion: false positive, not-the-weakness clause.
- **SARIF reference:** `runs[0].results[12]`, identity `4025e424-87b3-408b-9221-f967987b12c1`

The remaining 47 false positives are credential-shaped literals in test files, described here rather than quoted; the one other result of this kind, #27, is under Low — Needs manual review. The Technical Specification §6.4.4.5 undercounts this group: it gives 44 hard-coded-secret results, but the file holds 48 (24 + 20 + 3 + 1), and its tally sums to 80, not 84.

#### Result #2 — go/HardcodedPassword/test — pkg/detectors/planetscale/planetscale_test.go:17

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/planetscale/planetscale_test.go:17`
- **Summary:** `validPassword` in the PlanetScale pattern test is a 54-character random string shaped like a PlanetScale password.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/planetscale/planetscale_test.go:17` feeds an offline pattern test that calls `FromData` with verification off (`pkg/detectors/planetscale/planetscale_test.go:50`), and its invalid twin at `pkg/detectors/planetscale/planetscale_test.go:18` differs by one character. The test never contacts PlanetScale. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[2]`, identity `7049415b-7e8e-483f-b493-d39373cb86bf`

#### Result #3 — go/HardcodedPassword/test — pkg/detectors/planetscale/planetscale_test.go:33

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/planetscale/planetscale_test.go:33`
- **Summary:** The expected match of the same PlanetScale test joins the synthetic username and password.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/planetscale/planetscale_test.go:33` composes the values from `pkg/detectors/planetscale/planetscale_test.go:15-17` into the expected result of the offline test (`pkg/detectors/planetscale/planetscale_test.go:50`); it adds no new value. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[3]`, identity `dcf59854-fb8d-405b-adee-7c6690c747b7`

#### Result #4 — go/HardcodedPassword/test — pkg/detectors/planetscaledb/planetscaledb_test.go:17

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/planetscaledb/planetscaledb_test.go:17`
- **Summary:** `validPassword` in the PlanetScale database pattern test is a 53-character random string in PlanetScale's password format.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/planetscaledb/planetscaledb_test.go:17` is pattern-test input with verification off (`pkg/detectors/planetscaledb/planetscaledb_test.go:52`), and its invalid twin at `pkg/detectors/planetscaledb/planetscaledb_test.go:18` differs by one character. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[4]`, identity `80277a4e-09c0-42f2-b6c1-80c42c9da0ef`

#### Result #5 — go/HardcodedPassword/test — pkg/detectors/planetscaledb/planetscaledb_test.go:35

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/planetscaledb/planetscaledb_test.go:35`
- **Summary:** The expected match of the PlanetScale database test joins the PlanetScale host, username and password.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/planetscaledb/planetscaledb_test.go:35` composes the synthetic values from `pkg/detectors/planetscaledb/planetscaledb_test.go:15-19` into the expected result of the offline test (`pkg/detectors/planetscaledb/planetscaledb_test.go:52`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[5]`, identity `4444bd10-41ba-4825-a147-e8c0719820e7`

#### Result #6 — go/HardcodedPassword/test — pkg/detectors/redis/redis_test.go:21

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/redis/redis_test.go:21`
- **Summary:** `password` in the Redis tests is a 44-character random string used to build Azure-style Redis connection strings.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/redis/redis_test.go:21` declares the value that `pkg/detectors/redis/redis_test.go:22-23` compose into a valid and an invalid connection string; both Redis tests call `FromData` with verification off (`pkg/detectors/redis/redis_test.go:56`, `pkg/detectors/redis/redis_test.go:95`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[6]`, identity `63ea57a3-0b1e-4618-b9e0-dbad280c3cfd`

#### Result #7 — go/HardcodedPassword/test — pkg/detectors/redis/redis_test.go:22

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/redis/redis_test.go:22`
- **Summary:** `validAzureRedis` combines a synthetic Azure cache host with the synthetic password.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/redis/redis_test.go:22` joins the host at `pkg/detectors/redis/redis_test.go:19` and the password at `pkg/detectors/redis/redis_test.go:21` into the input of the valid-pattern case (`pkg/detectors/redis/redis_test.go:77`), which runs offline (`pkg/detectors/redis/redis_test.go:95`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[7]`, identity `ab242395-4a07-45f2-b22c-73c0a4f6b04f`

#### Result #8 — go/HardcodedPassword/test — pkg/detectors/redis/redis_test.go:23

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/redis/redis_test.go:23`
- **Summary:** `invalidAzureRedis` is the negative-case twin, built on a host that differs by one character.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/redis/redis_test.go:23` uses the altered host at `pkg/detectors/redis/redis_test.go:20`, and the invalid-pattern case expects no match (`pkg/detectors/redis/redis_test.go:82-83`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[8]`, identity `c33a1935-aaa5-44f8-a2e1-a3d626806f89`

#### Result #9 — go/HardcodedPassword/test — pkg/detectors/redis/redis_test.go:78

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/redis/redis_test.go:78`
- **Summary:** The expected result of the valid Redis pattern case is a `redis://` URI built from the synthetic password and test host.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/redis/redis_test.go:78` composes the values from `pkg/detectors/redis/redis_test.go:19` and `pkg/detectors/redis/redis_test.go:21` into an expectation checked offline (`pkg/detectors/redis/redis_test.go:95`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[9]`, identity `e9d06763-8ad2-47bc-9c9d-db12d91243e6`

#### Result #68 — go/HardcodedPassword/test — pkg/common/patterns_test.go:12

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/common/patterns_test.go:12`
- **Summary:** `passwordPattern` is a 13-character set of characters that a matched password must not contain, not a password.
- **Verdict:** False positive
- **Reasoning:** `TestPasswordRegexCheck` passes the constant at `pkg/common/patterns_test.go:12` to `PasswordRegexCheck` (`pkg/common/patterns_test.go:95`), which interpolates it into a negated character class (`pkg/common/patterns.go:67-68`). Criterion: false positive, not-the-weakness clause.
- **SARIF reference:** `runs[0].results[68]`, identity `8e621543-6ff9-4b91-bfd1-27060a06d20c`

#### Result #69 — go/HardcodedPassword/test — pkg/detectors/bitbucketapppassword/bitbucketapppassword_integration_test.go:29

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/bitbucketapppassword/bitbucketapppassword_integration_test.go:29`
- **Summary:** `invalidPassword` in the Bitbucket app-password integration test is a 31-character value its comment calls invalid but correctly formatted.
- **Verdict:** False positive
- **Reasoning:** The negative case at `pkg/detectors/bitbucketapppassword/bitbucketapppassword_integration_test.go:29` sits beside the real credentials, which come from the secret store (`pkg/detectors/bitbucketapppassword/bitbucketapppassword_integration_test.go:27-28`); the file builds only with the `detectors` tag (`pkg/detectors/bitbucketapppassword/bitbucketapppassword_integration_test.go:1`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[69]`, identity `9bca5b4f-b7b3-4681-9c05-4f807dcf1723`

#### Result #70 — go/HardcodedPassword/test — pkg/detectors/planetscale/planetscale_test.go:18

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/planetscale/planetscale_test.go:18`
- **Summary:** `invalidPassword` in the PlanetScale test is the negative-case twin of the synthetic password.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/planetscale/planetscale_test.go:18` differs from `pkg/detectors/planetscale/planetscale_test.go:17` by one character, and the invalid-pattern case expects no result (`pkg/detectors/planetscale/planetscale_test.go:36-38`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[70]`, identity `31332a38-92ef-448b-92f9-811b428e9fee`

#### Result #71 — go/HardcodedPassword/test — pkg/detectors/planetscaledb/planetscaledb_test.go:18

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/planetscaledb/planetscaledb_test.go:18`
- **Summary:** `invalidPassword` in the PlanetScale database test is the negative-case twin of the synthetic password.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/planetscaledb/planetscaledb_test.go:18` differs from `pkg/detectors/planetscaledb/planetscaledb_test.go:17` by one character, and the invalid-pattern case expects no result (`pkg/detectors/planetscaledb/planetscaledb_test.go:38-40`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[71]`, identity `5bec78a2-12a8-4067-ab25-55c3abc2043f`

#### Result #72 — go/HardcodedPassword/test — pkg/detectors/docker/docker_auth_config_test.go:218

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:218`
- **Summary:** A `Test_ParseAuth` case sets the password field to the placeholder `my_password`.
- **Verdict:** False positive
- **Reasoning:** The placeholder at `pkg/detectors/docker/docker_auth_config_test.go:218` is only parsed by `parseBasicAuth` (`pkg/detectors/docker/docker_auth_config_test.go:256`), and the test case names no registry, so it authenticates to nothing. Criterion: false positive, test-data clause (placeholder).
- **SARIF reference:** `runs[0].results[72]`, identity `4aea4810-785b-4b27-bf52-d81dce9c2154`

#### Result #73 — go/HardcodedPassword/test — pkg/detectors/docker/docker_auth_config_test.go:224

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:224`
- **Summary:** The `Test_ParseAuth` case that combines an auth string with explicit fields uses the same `my_password` placeholder.
- **Verdict:** False positive
- **Reasoning:** The placeholder at `pkg/detectors/docker/docker_auth_config_test.go:224` belongs to the case at `pkg/detectors/docker/docker_auth_config_test.go:221-225`, which is only parsed (`pkg/detectors/docker/docker_auth_config_test.go:256`) and names no registry. Criterion: false positive, test-data clause (placeholder).
- **SARIF reference:** `runs[0].results[73]`, identity `8b7c28d3-15a6-4524-8ab4-3bb59596008a`

#### Result #74 — go/HardcodedPassword/test — pkg/detectors/jdbc/sqlserver_test.go:235

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/jdbc/sqlserver_test.go:235`
- **Summary:** A SQL Server connection-string test uses a 7-character password for a `localhost` database.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/jdbc/sqlserver_test.go:235` belongs to connection info for `localhost`, database `testdb` and user `sa` (`pkg/detectors/jdbc/sqlserver_test.go:231-235`), which the test only formats into a string and inspects (`pkg/detectors/jdbc/sqlserver_test.go:249-255`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[74]`, identity `3d38a666-9c6f-48f5-9acb-bef24bccb72c`

#### Result #75 — go/HardcodedPassword/test — pkg/sources/gitlab/gitlab_integration_test.go:246

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/gitlab/gitlab_integration_test.go:246`
- **Summary:** The GitLab integration test's "basic auth did not authenticate" case uses the password `bad-password`.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/sources/gitlab/gitlab_integration_test.go:246` is a negative case that must fail (`pkg/sources/gitlab/gitlab_integration_test.go:241-250`); the real tokens come from the secret store (`pkg/sources/gitlab/gitlab_integration_test.go:231-232`), and the file builds only with the `integration` tag (`pkg/sources/gitlab/gitlab_integration_test.go:1`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[75]`, identity `0b57a5ac-e85e-48b5-960e-f25a2718a83a`

#### Result #76 — go/HardcodedPassword/test — pkg/sources/jenkins/jenkins_test.go:141

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/jenkins/jenkins_test.go:141`
- **Summary:** The Jenkins source test authenticates with the password `testpass` to a local mock server.
- **Verdict:** False positive
- **Reasoning:** The credential at `pkg/sources/jenkins/jenkins_test.go:141` goes only to the `httptest` server from `createMockJenkinsServer` (`pkg/sources/jenkins/jenkins_test.go:50-52`, `pkg/sources/jenkins/jenkins_test.go:132-137`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[76]`, identity `a15cf4b6-e0d1-42e2-bdd7-d04bb1c0d560`

#### Result #77 — go/HardcodedPassword/test — pkg/sources/jenkins/unit_test.go:121

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/jenkins/unit_test.go:121`
- **Summary:** The Jenkins unit-test helper builds a connection with the password `testpass`.
- **Verdict:** False positive
- **Reasoning:** `newTestSource` sets the value at `pkg/sources/jenkins/unit_test.go:121` (`pkg/sources/jenkins/unit_test.go:113-124`), and its callers pass the URL of an `httptest` server (`pkg/sources/jenkins/unit_test.go:69`, `pkg/sources/jenkins/unit_test.go:149`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[77]`, identity `6820126e-5e46-45ad-8969-3a7b11d61401`

#### Result #78 — go/HardcodedPassword/test — pkg/detectors/jdbc/sqlserver_test.go:126

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/jdbc/sqlserver_test.go:126`
- **Summary:** `wantPassword` is the password a SQL Server JDBC parse test expects to extract, the word `testpassword`.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/jdbc/sqlserver_test.go:126` is an expectation for parsing a `localhost` connection string (`pkg/detectors/jdbc/sqlserver_test.go:121-131`); nothing connects to a server. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[78]`, identity `0fc2f6ad-621c-4a2a-8357-5d5fddc45f33`

#### Result #79 — go/HardcodedPassword/test — pkg/detectors/jdbc/sqlserver_test.go:149

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/jdbc/sqlserver_test.go:149`
- **Summary:** The same test compares the parsed password with `wantPassword`.
- **Verdict:** False positive
- **Reasoning:** `pkg/detectors/jdbc/sqlserver_test.go:149` reads the expectation declared at `pkg/detectors/jdbc/sqlserver_test.go:126`; it introduces no value of its own. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[79]`, identity `5570dd9c-3e38-4131-875b-fb0882d01e52`

#### Result #80 — go/HardcodedPassword/test — pkg/detectors/ldap/ldap_test.go:21

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/ldap/ldap_test.go:21`
- **Summary:** `validPasswordPattern` in the LDAP pattern test is a 30-character synthetic password for an LDAP URI on `localhost`.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/ldap/ldap_test.go:21` pairs with a `localhost` URI (`pkg/detectors/ldap/ldap_test.go:17`), and the test calls `FromData` with verification off (`pkg/detectors/ldap/ldap_test.go:55`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[80]`, identity `0e092e4d-38fc-4687-9d6d-39b6b2586776`

#### Result #81 — go/HardcodedPassword/test — pkg/detectors/mrticktock/mrticktock_test.go:17

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/mrticktock/mrticktock_test.go:17`
- **Summary:** `validPasswordPattern` in the MrTickTock pattern test is a 23-character random string paired with an e-mail address at an example domain.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/mrticktock/mrticktock_test.go:17` goes with the example address at `pkg/detectors/mrticktock/mrticktock_test.go:15`, its twin at `pkg/detectors/mrticktock/mrticktock_test.go:18` differs by one character, and the test runs with verification off (`pkg/detectors/mrticktock/mrticktock_test.go:55`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[81]`, identity `6b4f9d59-aeb4-411a-8451-51e3fd5b8a08`

#### Result #82 — go/HardcodedPassword/test — pkg/detectors/ldap/ldap_test.go:22

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/ldap/ldap_test.go:22`
- **Summary:** `invalidPasswordPattern` in the LDAP test is the password used by the invalid-pattern case.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/ldap/ldap_test.go:22` is input to a case that expects no result (`pkg/detectors/ldap/ldap_test.go:41-43`), offline like the rest of the test (`pkg/detectors/ldap/ldap_test.go:55`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[82]`, identity `c07aeb36-b593-442a-ad38-859f2d1e780d`

#### Result #83 — go/HardcodedPassword/test — pkg/detectors/mrticktock/mrticktock_test.go:18

- **Rule:** `go/HardcodedPassword/test` — Use of Hardcoded Passwords, CWE-798, CWE-259
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/mrticktock/mrticktock_test.go:18`
- **Summary:** `invalidPasswordPattern` in the MrTickTock test is the negative-case twin of the synthetic password.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/mrticktock/mrticktock_test.go:18` differs from `pkg/detectors/mrticktock/mrticktock_test.go:17` by one character, and its case expects no result (`pkg/detectors/mrticktock/mrticktock_test.go:40-43`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[83]`, identity `2154be2f-199d-4bb2-9631-b8d35a58919f`

#### Result #13 — go/NoHardcodedCredentials/test — pkg/analyzer/analyzers/dockerhub/dockerhub_test.go:59

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/analyzer/analyzers/dockerhub/dockerhub_test.go:59`
- **Summary:** A Docker Hub analyzer test builds a mock user record with an ID, username and e-mail address.
- **Verdict:** False positive
- **Reasoning:** The record at `pkg/analyzer/analyzers/dockerhub/dockerhub_test.go:59` only feeds `secretInfoToAnalyzerResult` (`pkg/analyzer/analyzers/dockerhub/dockerhub_test.go:57-64`), and the test never calls Docker Hub. A user identity with no password or token is not a secret. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[13]`, identity `7df98104-a0dc-48fb-a4e5-40ff850635c7`

#### Result #14 — go/NoHardcodedCredentials/test — pkg/analyzer/analyzers/huggingface/huggingface_test.go:128

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/analyzer/analyzers/huggingface/huggingface_test.go:128`
- **Summary:** A Hugging Face analyzer test sets the mock token owner's username to `testuser`.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/analyzer/analyzers/huggingface/huggingface_test.go:128` is part of mock token metadata for a result-shaping test (`pkg/analyzer/analyzers/huggingface/huggingface_test.go:125-127`); a username alone is not a secret. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[14]`, identity `6770795a-10b3-42ae-8063-c4e2330f60a1`

#### Result #15 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:217

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:217`
- **Summary:** A `Test_ParseAuth` case sets the username field to the placeholder `my_username`.
- **Verdict:** False positive
- **Reasoning:** The placeholder at `pkg/detectors/docker/docker_auth_config_test.go:217` is only parsed by `parseBasicAuth` (`pkg/detectors/docker/docker_auth_config_test.go:256`) and names no registry. Criterion: false positive, test-data clause (placeholder).
- **SARIF reference:** `runs[0].results[15]`, identity `e0657f73-b437-4fe1-ae16-dda62ee4f6f4`

#### Result #16 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:223

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:223`
- **Summary:** The `Test_ParseAuth` case that combines an auth string with explicit fields uses the `my_username` placeholder.
- **Verdict:** False positive
- **Reasoning:** The placeholder at `pkg/detectors/docker/docker_auth_config_test.go:223` belongs to the case at `pkg/detectors/docker/docker_auth_config_test.go:221-225`, which is only parsed (`pkg/detectors/docker/docker_auth_config_test.go:256`). Criterion: false positive, test-data clause (placeholder).
- **SARIF reference:** `runs[0].results[16]`, identity `25389691-6c9d-4915-b0dd-d211a1f96095`

#### Result #17 — go/NoHardcodedCredentials/test — pkg/sources/github/github_integration_test.go:205

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/github/github_integration_test.go:205`
- **Summary:** A GitHub integration test expects chunks whose metadata names the account `truffle-sandbox`.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/sources/github/github_integration_test.go:205` is expected result metadata, not a credential; the test's real credentials come from the secret store at run time (`pkg/sources/github/github_integration_test.go:159-165`), and the file builds only with the `integration` tag (`pkg/sources/github/github_integration_test.go:1`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[17]`, identity `3410a927-626f-45d6-aacd-1737e8c19d09`

#### Result #18 — go/NoHardcodedCredentials/test — pkg/sources/github/github_integration_test.go:235

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/github/github_integration_test.go:235`
- **Summary:** The pull-request comment case of the same test expects the same `truffle-sandbox` account name.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/sources/github/github_integration_test.go:235` is expected metadata for a case whose token is `githubToken` from the secret store (`pkg/sources/github/github_integration_test.go:222-224`); the file builds only with the `integration` tag (`pkg/sources/github/github_integration_test.go:1`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[18]`, identity `ea6c86c3-2f5b-4e81-979e-75e8f941d60e`

#### Result #19 — go/NoHardcodedCredentials/test — pkg/sources/github/github_integration_test.go:1072

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/github/github_integration_test.go:1072`
- **Summary:** An unauthenticated GitHub integration test expects the `truffle-sandbox` account name in chunk metadata.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/sources/github/github_integration_test.go:1072` is expected metadata for a connection with no credential (`pkg/sources/github/github_integration_test.go:1062`), in a file built only with the `integration` tag (`pkg/sources/github/github_integration_test.go:1`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[19]`, identity `ac57cea9-008c-4907-82a8-8c3857992337`

#### Result #20 — go/NoHardcodedCredentials/test — pkg/sources/gitlab/gitlab_integration_test.go:245

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/gitlab/gitlab_integration_test.go:245`
- **Summary:** The GitLab "basic auth did not authenticate" case uses the username `bad-user`.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/sources/gitlab/gitlab_integration_test.go:245` is a negative case that must fail (`pkg/sources/gitlab/gitlab_integration_test.go:241-250`); the real tokens come from the secret store (`pkg/sources/gitlab/gitlab_integration_test.go:231-232`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[20]`, identity `252f2d7b-9a0a-4556-bea7-8de0b9c17b45`

#### Result #21 — go/NoHardcodedCredentials/test — pkg/sources/jenkins/jenkins_test.go:140

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/jenkins/jenkins_test.go:140`
- **Summary:** The Jenkins source test logs in to a local mock server as `testuser`.
- **Verdict:** False positive
- **Reasoning:** The username at `pkg/sources/jenkins/jenkins_test.go:140` goes only to the `httptest` server from `createMockJenkinsServer` (`pkg/sources/jenkins/jenkins_test.go:50-52`, `pkg/sources/jenkins/jenkins_test.go:132-137`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[21]`, identity `85fcbc74-3f84-43e3-b844-0e67874191a6`

#### Result #22 — go/NoHardcodedCredentials/test — pkg/sources/jenkins/unit_test.go:120

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/jenkins/unit_test.go:120`
- **Summary:** The Jenkins unit-test helper builds a connection for the user `testuser`.
- **Verdict:** False positive
- **Reasoning:** `newTestSource` sets the value at `pkg/sources/jenkins/unit_test.go:120` (`pkg/sources/jenkins/unit_test.go:113-124`), and its callers point it at an `httptest` server (`pkg/sources/jenkins/unit_test.go:69`, `pkg/sources/jenkins/unit_test.go:149`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[22]`, identity `c6f5c872-3d29-443d-bc5e-1b831e91919d`

#### Result #23 — go/NoHardcodedCredentials/test — pkg/sources/travisci/travisci_test.go:51

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/travisci/travisci_test.go:51`
- **Summary:** The Travis CI source test expects chunk metadata naming the account `truffle-sandbox`.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/sources/travisci/travisci_test.go:51` is expected metadata; the token the test uses comes from the secret store (`pkg/sources/travisci/travisci_test.go:20-24`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[23]`, identity `1e452103-0bde-41cf-b363-8d2998a94489`

#### Result #24 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:209

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:209`
- **Summary:** The first `Test_ParseAuth` case is a 28-character base64 `auth` string that decodes to a short username-and-password pair.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/docker/docker_auth_config_test.go:209` is only decoded by `parseBasicAuth` (`pkg/detectors/docker/docker_auth_config_test.go:255-256`); the test names no registry host, so as found the pair authenticates to nothing. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[24]`, identity `2f9073db-c5ac-4a1e-898c-22c2012a6fe1`

#### Result #25 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:213

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:213`
- **Summary:** The "auth with colon" case is a base64 `auth` string encoding a UUID-shaped username and a 32-character password that itself contains a colon.
- **Verdict:** False positive
- **Reasoning:** The case at `pkg/detectors/docker/docker_auth_config_test.go:211-214` checks that parsing splits on the first colon only (`pkg/detectors/docker/docker_auth_config_test.go:213`), and the test only decodes it (`pkg/detectors/docker/docker_auth_config_test.go:256`); with no registry host it authenticates to nothing. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[25]`, identity `1a449a59-6099-42f2-b4b6-2389240f9f99`

#### Result #26 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:222

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:222`
- **Summary:** A `Test_ParseAuth` case supplies, as base64, the same `my_username` and `my_password` placeholders its explicit fields hold.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/docker/docker_auth_config_test.go:222` encodes the placeholders set at `pkg/detectors/docker/docker_auth_config_test.go:223-224`, and the test only parses it (`pkg/detectors/docker/docker_auth_config_test.go:256`). Criterion: false positive, test-data clause (placeholder).
- **SARIF reference:** `runs[0].results[26]`, identity `2abec70e-2827-41e0-a7d8-9a6b0a5b143a`

#### Result #28 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:246

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:246`
- **Summary:** An error case of `Test_ParseAuth` is a base64 `auth` string whose decoded form has no colon.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/docker/docker_auth_config_test.go:246` must be rejected, with an empty expected result (`pkg/detectors/docker/docker_auth_config_test.go:244-247`, `pkg/detectors/docker/docker_auth_config_test.go:258-262`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[28]`, identity `e311463b-7687-4384-83d4-963a092b9fbd`

#### Result #29 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:250

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:250`
- **Summary:** Another error case of `Test_ParseAuth` is a 22-character `auth` string that is not valid base64.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/docker/docker_auth_config_test.go:250` must be rejected (`pkg/detectors/docker/docker_auth_config_test.go:248-251`, `pkg/detectors/docker/docker_auth_config_test.go:258-262`). Criterion: false positive, test-data clause (negative case).
- **SARIF reference:** `runs[0].results[29]`, identity `93f4817b-1795-4059-8aab-f4b4a11b68ad`

#### Result #30 — go/NoHardcodedCredentials/test — pkg/detectors/jdbc/postgres_test.go:192

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/jdbc/postgres_test.go:192`
- **Summary:** A PostgreSQL connection-string test uses the default user name `postgres` for a `localhost` database.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/jdbc/postgres_test.go:192` is part of connection info for `localhost` and `testdb` that the test only formats into a string (`pkg/detectors/jdbc/postgres_test.go:181-193`); a user name is not a secret. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[30]`, identity `43bdbdcc-9639-418c-867b-7925524a1387`

#### Result #31 — go/NoHardcodedCredentials/test — pkg/sources/github/github_test.go:827

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/github/github_test.go:827`
- **Summary:** A GitHub source test caches a mock repository whose owner login is `cached-user`.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/sources/github/github_test.go:827` names the owner of a repository the test caches by hand to check that enumeration makes no duplicate API calls (`pkg/sources/github/github_test.go:820-831`); a login is not a secret. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[31]`, identity `66f9ee6a-4c5b-4308-80ae-19e060f4397c`

#### Result #32 — go/NoHardcodedCredentials/test — pkg/sources/github/github_test.go:830

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/sources/github/github_test.go:830`
- **Summary:** The same mock repository sets its owner's `Login` from that login variable.
- **Verdict:** False positive
- **Reasoning:** `pkg/sources/github/github_test.go:830` reuses the value from `pkg/sources/github/github_test.go:827` and adds none of its own. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[32]`, identity `075d85a5-c40c-4c14-9a4c-561f17364aff`

#### Result #1 — go/HardcodedNonCryptoSecret/test — pkg/detectors/githubapp/githubapp_test.go:29

- **Rule:** `go/HardcodedNonCryptoSecret/test` — Hardcoded Non-Cryptographic Secret, CWE-547
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/githubapp/githubapp_test.go:29`
- **Summary:** The expected secret in the GitHub App pattern test is a 118-character PEM block, only a header, 58 characters of body and a footer.
- **Verdict:** False positive
- **Reasoning:** The value at `pkg/detectors/githubapp/githubapp_test.go:29` is far too short to hold an RSA key, so it is a truncated, unparseable key rather than a credential; the test checks the pattern offline (`pkg/detectors/githubapp/githubapp_test.go:44`, `pkg/detectors/githubapp/githubapp_test.go:56`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[1]`, identity `e2919506-7e49-4e60-b551-105e45c51a0b`

#### Result #34 — go/HardcodedNonCryptoSecret/test — pkg/detectors/privatekey/privatekey_test.go:15

- **Rule:** `go/HardcodedNonCryptoSecret/test` — Hardcoded Non-Cryptographic Secret, CWE-547
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/privatekey/privatekey_test.go:15`
- **Summary:** `validPattern` in the private-key pattern test is an RSA private key in PEM form.
- **Verdict:** False positive
- **Reasoning:** The key at `pkg/detectors/privatekey/privatekey_test.go:15` names no service, account or host, so as found it authenticates to nothing; it is pattern-test input with verification off (`pkg/detectors/privatekey/privatekey_test.go:65`), next to an invalid twin (`pkg/detectors/privatekey/privatekey_test.go:25`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[34]`, identity `75faedeb-bb2b-4d5d-bd19-79a7cf00cf69`

#### Result #67 — go/HardcodedNonCryptoSecret/test — pkg/detectors/privatekey/privatekey_test.go:103

- **Rule:** `go/HardcodedNonCryptoSecret/test` — Hardcoded Non-Cryptographic Secret, CWE-547
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/privatekey/privatekey_test.go:103`
- **Summary:** `encryptedUncrackablePattern` is a passphrase-protected ed25519 private key.
- **Verdict:** False positive
- **Reasoning:** The comment at `pkg/detectors/privatekey/privatekey_test.go:100-102` states that its passphrase is deliberately absent from the detector's wordlist, so the key at `pkg/detectors/privatekey/privatekey_test.go:103` cannot be unlocked; `TestPrivatekey_EncryptedKeyReported` only checks that it is still reported (`pkg/detectors/privatekey/privatekey_test.go:113-120`). Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[67]`, identity `0d7b1a3a-b0b7-4df4-a11b-54e48b92ff91`

#### Result #66 — python/HardcodedNonCryptoSecret/test — backend/tests/test_parse.py:26

- **Rule:** `python/HardcodedNonCryptoSecret/test` — Hardcoded Non-Cryptographic Secret, CWE-547
- **Severity:** Low (SARIF level `note`)
- **Location:** `backend/tests/test_parse.py:26`
- **Summary:** `TARGET_SECRET` is a 16-character probe string planted in test repository URLs.
- **Verdict:** False positive
- **Reasoning:** The value at `backend/tests/test_parse.py:26` is inserted into the credential part of the target URLs at `backend/tests/test_parse.py:28-46`, so that `test_redact_target` and related tests can assert it never survives redaction (`backend/tests/test_parse.py:322`, `backend/tests/test_parse.py:340`, `backend/tests/test_parse.py:352`). It authenticates to nothing. Criterion: false positive, test-data clause.
- **SARIF reference:** `runs[0].results[66]`, identity `4f5b26c2-110c-4275-8507-01ab768bd73b`

### Low — Needs manual review

#### Result #27 — go/NoHardcodedCredentials/test — pkg/detectors/docker/docker_auth_config_test.go:229

- **Rule:** `go/NoHardcodedCredentials/test` — Use of Hardcoded Credentials, CWE-798
- **Severity:** Low (SARIF level `note`)
- **Location:** `pkg/detectors/docker/docker_auth_config_test.go:229`
- **Summary:** A `Test_ParseAuth` case holds, as its base64 `auth` value, a complete Google Cloud service-account key, and holds the decoded form as the expected result.
- **Verdict:** Needs manual review
- **Reasoning:** The encoded value spans `pkg/detectors/docker/docker_auth_config_test.go:229-240`, of which Snyk flags only the first line, and the decoded copy is at `pkg/detectors/docker/docker_auth_config_test.go:241`: a `_json_key` login whose password is a service-account JSON document with its private key, client e-mail address and project. The comment at `pkg/detectors/docker/docker_auth_config_test.go:226-227` calls these Kubernetes public test credentials and links the upstream Kubernetes e2e test at a pinned commit, and the test only decodes the value (`pkg/detectors/docker/docker_auth_config_test.go:256`); nothing in the repository sends it anywhere. Publication proves the key is exposed, not that it is disabled, and the repository holds no evidence of revocation, so the published-test-value part of the test-data clause cannot be shown to hold. Missing evidence: confirmation from the key's owner, or from Google Cloud, that the key is disabled. The key was not tested live, and this report reproduces no field of it. This also contradicts the Technical Specification §6.6.2.4, which says no test credential is committed: that holds for the project's own live test credentials, which integration tests load at run time (`pkg/sources/github/github_integration_test.go:31-42`), but not for this third-party fixture. Criterion: needs manual review, external-evidence clause.
- **SARIF reference:** `runs[0].results[27]`, identity `c47b36b5-14fd-4219-8bb5-3bc3ff23f391`

## Blitzy remediation plan for true positives

The prompt below covers the 12 true positives, #53–#63 and #65, in three changes, listed in the table. It is a proposal for a separate Blitzy run: it has not been run, and nothing in the repository has changed. The false positives need no change, and #27 is excluded until its manual review returns a verdict.

| Change | Results | File changed | Fix |
| --- | --- | --- | --- |
| A, ngrok pagination origin | #53–#60 | `pkg/analyzer/analyzers/ngrok/requests.go` | In `fetchResources` (`pkg/analyzer/analyzers/ngrok/requests.go:190-209`), parse the URL and return an error unless its scheme is `https` and its host equals the host of `ngrokAPIBaseURL` (`pkg/analyzer/analyzers/ngrok/requests.go:14`). `makeAPIRequest` and the six loops stay as they are; every loop passes `res.NextPageURI` to `fetchResources` (`pkg/analyzer/analyzers/ngrok/requests.go:97` and the five matching lines), so one check covers all eight results. |
| B, Docker local addresses | #61–#63 | `pkg/detectors/docker/docker_auth_config.go` | In `FromData`, replace the `common.SaneHttpClient()` fallback (`pkg/detectors/docker/docker_auth_config.go:127-131`) with `detectors.DetectorHttpClientWithNoLocalAddresses` (`pkg/detectors/http.go:40-45`) and drop the `pkg/common` import (`pkg/detectors/docker/docker_auth_config.go:16`), whose only use is that fallback; keep the injected `s.client` path. `verifyMatch` sends both requests on that client (`pkg/detectors/docker/docker_auth_config.go:165`, `pkg/detectors/docker/docker_auth_config.go:218`), its dial guard refuses loopback, link-local, private and unspecified addresses (`pkg/detectors/http.go:101-152`), and 49 other non-test detector files already use it. |
| C, Jenkins TLS opt-in | #65 | `pkg/sources/jenkins/jenkins.go` | Keep `--insecure-skip-verify-tls` / `JENKINS_INSECURE_SKIP_VERIFY_TLS` (`main.go:262`), its wiring (`pkg/engine/jenkins.go:64`) and `roundtripper.WithInsecureTLS`. In `Source.Init`, when `conn.GetInsecureSkipVerifyTls()` is true (`pkg/sources/jenkins/jenkins.go:89-92`), log through `aCtx.Logger()` at default verbosity that certificate verification is disabled for this source. |

```text
Fix security vulnerabilities in TruffleHog. Address only the
identified vulnerabilities without modifying unrelated code.

VULNERABILITY ASSESSMENT

- What specific vulnerabilities need to be fixed?
  Snyk Code findings from results.sarif (SnykCode 1.1307.3); no CVE is assigned to any of them.
  - Result #53 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:92 (change A, CWE-918)
  - Result #54 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:109 (change A, CWE-918)
  - Result #55 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:126 (change A, CWE-918)
  - Result #56 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:143 (change A, CWE-918)
  - Result #57 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:160 (change A, CWE-918)
  - Result #58 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:177 (change A, CWE-918)
  - Result #59 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:192 (change A, CWE-918)
  - Result #60 — go/Ssrf — pkg/analyzer/analyzers/ngrok/requests.go:244 (change A, CWE-918)
  - Result #61 — go/Ssrf — pkg/detectors/docker/docker_auth_config.go:133 (change B, CWE-918)
  - Result #62 — go/Ssrf — pkg/detectors/docker/docker_auth_config.go:155 (change B, CWE-918)
  - Result #63 — go/Ssrf — pkg/detectors/docker/docker_auth_config.go:204 (change B, CWE-918)
  - Result #65 — go/TooPermissiveTrustManager — pkg/roundtripper/roundtripper.go:126 (change C, CWE-295)
- What is the severity of each?
  All twelve are Medium (SARIF level warning).
  - A, #53-#60: whoever controls the api.ngrok.com response can make the analyzer send the analysed ngrok key as a Bearer token to any host the scanner can reach. SECURITY.md:7-8 treats sending a discovered credential to an attacker-controlled endpoint as CVE-class credential exfiltration. Likelihood is low, because it needs control of the TLS-authenticated ngrok API response.
  - B, #61-#63: scanned content can make the scanner send blind GET requests, carrying the content's own credential, to internal and cloud-metadata addresses. SECURITY.md:4 and SECURITY.md:11-14 class this as hardening.
  - C, #65: once the operator enables the switch, a network attacker can intercept the Jenkins credentials.
- What compliance frameworks apply?
  None is named in the repository: a search for SOC 2, PCI-DSS and HIPAA matches only a checksum substring in go.sum. The internal standard that applies is the Blind SSRF & Outbound Request Policy in SECURITY.md:3-15.

SCOPE

- What components are affected?
  - Change A: pkg/analyzer/analyzers/ngrok/requests.go, function fetchResources (lines 190-209).
  - Change B: pkg/detectors/docker/docker_auth_config.go, function FromData (client fallback at lines 127-131, pkg/common import at line 16).
  - Change C: pkg/sources/jenkins/jenkins.go, method Source.Init (lines 89-92).
  - pkg/roundtripper/roundtripper.go:126, the construct flagged by #65, stays unchanged.
  - New tests in pkg/analyzer/analyzers/ngrok/, pkg/detectors/docker/ and pkg/sources/jenkins/, listed under the security tests below.
- What must remain untouched?
  - The CLI flags and environment variables, including --insecure-skip-verify-tls and JENKINS_INSECURE_SKIP_VERIFY_TLS, so docs/man/trufflehog.1 needs no regeneration.
  - The sourcespb Jenkins insecure_skip_verify_tls field and its wiring at pkg/engine/jenkins.go:64.
  - roundtripper.WithInsecureTLS, and pkg/detectors/http.go.
  - The Docker detector's FromData signature, its Result fields and the s.client injection that tests use.
  - The ngrok analyzer's output, pkg/analyzer/analyzers/ngrok/expected_output.json.
  - results.sarif, and every file flagged by the other 72 results.

TECHNICAL IMPLEMENTATION

- How should fixes be implemented?
  - Change A: in fetchResources, parse the URL with net/url and return an error, before any request is sent, unless the scheme is https and the host equals the host of ngrokAPIBaseURL (pkg/analyzer/analyzers/ngrok/requests.go:14). Leave makeAPIRequest and the six pagination loops unchanged; they all pass res.NextPageURI to fetchResources, so one check covers #53-#60.
  - Change B: in FromData, replace the common.SaneHttpClient() fallback with detectors.DetectorHttpClientWithNoLocalAddresses and remove the pkg/common import, whose only use is that fallback; keep the injected s.client path. Behaviour change: the shared client follows no redirects and uses the 10 s detector timeout (pkg/detectors/http.go:25) instead of 5 s (pkg/common/http.go:245), so a registry that answers /v2/ with a redirect now yields a verification error, as it already does for the other detectors on that client.
  - Change C: in Source.Init, when conn.GetInsecureSkipVerifyTls() is true, log through aCtx.Logger() at default verbosity that TLS certificate verification is disabled for this source. Residual: a re-scan still reports #65, because the insecure construct stays by design. Removing the switch would change the CLI and the sourcespb Jenkins message, so that decision is left to the project owner.
- What dependencies need updating?
  None. All three changes are first-party code and go.mod stays unchanged; no finding names a vulnerable package.

TESTING & VALIDATION

- What security tests should verify the fixes?
  - Change A: an offline unit test in pkg/analyzer/analyzers/ngrok/ showing that fetchResources returns an error before sending anything for an http://127.0.0.1:PORT URL served by httptest, for http://169.254.169.254/, for another https host and for http://api.ngrok.com/, with the httptest server recording no request.
  - Change B: a unit test in pkg/detectors/docker/ in which a Scanner with no injected client runs FromData with verification on, for content whose auths key is the httptest server's http://127.0.0.1:PORT address; the result is unverified with a verification error, and the server records no request.
  - Change C: a unit test in pkg/sources/jenkins/ showing that the warning is logged when insecure_skip_verify_tls is set, and not otherwise.
  - Scanner check: run SNYK_TOKEN=${SNYK_TOKEN} snyk code test --sarif-file-output=PATH, with PATH outside the repository. The new file must hold no go/Ssrf result in pkg/analyzer/analyzers/ngrok/requests.go or pkg/detectors/docker/docker_auth_config.go, must still hold the go/TooPermissiveTrustManager result in pkg/roundtripper/roundtripper.go (the change C residual), and must hold no ruleId and uri pair that results.sarif lacks. Do not compare line numbers, because the fixes move lines. Record, with its reason, any result Snyk still reports although its change is in place; do not suppress it.
- What regression tests confirm existing functionality?
  - CGO_ENABLED=0 go test ./pkg/detectors/docker/ ./pkg/sources/jenkins/ runs the offline unit suites, including Test_ParseAuth (pkg/detectors/docker/docker_auth_config_test.go:205) and Test_ParseAuthenticateHeader (pkg/detectors/docker/docker_auth_config_test.go:271).
  - TEST_SECRET_FILE=${TEST_SECRET_FILE} CGO_ENABLED=0 go test ./pkg/analyzer/analyzers/ngrok/ runs TestAnalyzer_Analyze, which reads the NGROK key through common.GetSecret (pkg/analyzer/analyzers/ngrok/ngrok_test.go:22-27); GetSecret loads the dotenv file named by TEST_SECRET_FILE (pkg/common/secrets.go:46-49). Its output must still match expected_output.json, which also shows that change A accepts real api.ngrok.com pagination.
  - TEST_SECRET_FILE=${TEST_SECRET_FILE} CGO_ENABLED=0 go test -tags=detectors ./pkg/detectors/docker/ runs the credentialed Docker integration test.
  - make check runs go fmt and go vet over the module (Makefile:21-23).

CONSTRAINTS

- Make only the minimal necessary changes to remediate each vulnerability.
- Do not modify code unrelated to the security findings.
- Use placeholder pattern (${SECRET_NAME}) for all credentials.
```

## Scan coverage and limitations

- One `.go` file failed to parse: `runs[0].properties.coverage` lists it as `FAILED_PARSING` without naming it. Findings in that file cannot appear in the scan, and this report does not analyse it.
- The report covers the 84 SARIF results only. It is not a review for weaknesses the scan did not report.
- The SARIF does not record the scanned revision: `runs[0]` has no `versionControlProvenance`, `invocations` or `originalUriBaseIds`. Commit `73890ab3c` differs from its parent `05b4b69b6` only by adding `results.sarif`, and the scan time, 11:48:01Z, precedes the commit time, 11:51:51Z. That is consistent with a scan of `05b4b69b6`, but it is not proof.
- Every citation was checked at commit `73890ab3c`, where each of the 84 flagged lines still holds the construct its rule describes, so no result needed relocating.
- The Technical Specification §6.4.4.5 describes the 19 path-traversal results as source-connector reads of operator-named paths; in fact one is in the permissions generator (#33) and ten are in `pkg/sources/git/git_test.go` (#43–#52).
- The README's example that writes `results.sarif` with `--sarif` (`README.md:790-794`) describes TruffleHog's own SARIF output, not this Snyk Code file.
