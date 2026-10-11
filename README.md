`arc-audit` checks Solidity for reentrancy, pre-0.8 overflow, unchecked calls, `tx.origin`, `delegatecall`, and storage-loop gas risks. It reports SWC findings as JSON and exits 1 on high or critical issues. No compiler required.

### Technical Overview

`arc-audit` is a static analysis engine for the ARC Microgrants Program. It audits Solidity from source text alone: no `solc`, no node, no third-party packages. The scanner keeps a structural model of each file — pragma version range, contracts, inherited state variables in that file, and function bodies — and reports SWC findings against that model.

A line-wide regular expression cannot do this. It treats a `.call` in one function and a `balances[...] =` in a later function as one reentrancy bug, and it treats the same tokens inside comments and strings as code. `arc-audit` compares call order and state writes only inside the function that contains both, and it classifies the pragma (`^0.7.6`, `0.7.6`, `>=0.4.22 <0.9.0`, `^0.8.0 || ^0.8.19`) before it decides whether an arithmetic operator can wrap.

### Core Architectural Features

- **Context-aware reentrancy (SWC-107).** External calls (`.call`, `.delegatecall`, `.send`, `.transfer`, token `transfer` / `transferFrom`) and storage writes are ordered by source position inside one function. A write that belongs to another function is ignored. Writes that only release a lock (`locked`, `_status`, and the same family) after the call are ignored. A balance update that still sits after the call is reported, with both line numbers. If the function carries a modifier whose name contains `reentr` (OpenZeppelin's `nonReentrant`), the reentrancy finding is suppressed.
- **Lexical comment masking.** `//` and `/* */` comments are replaced with spaces. Newlines and string indexes stay put, so a finding's line number is the line in the file the author opened. String literals are masked the same way before a detector runs, so a `.call` inside a revert string is not a call.
- **Compiler version-range matching (SWC-101).** The pragma is parsed as an npm-style Solidity constraint, including `^`, `~`, comparison operators, and `||`. The result is `yes` (every allowed compiler is 0.8+), `no` (none are), `partial` (the range crosses 0.8), or `unknown`. Raw `+`, `-`, `*`, `/`, and compound assignments are flagged when checks are absent. On 0.8+ they are flagged only inside `unchecked`. A library named `SafeMath` is skipped. `using SafeMath` does not silence a raw `a - b`; only calls such as `.sub` and `.add` do.
- **SWC coverage beyond the two ledger bugs.** The same pass reports `tx.origin` authorization (SWC-115), ignored low-level and token return values (SWC-104), `delegatecall` (SWC-112), unprotected `selfdestruct` (SWC-106), withdrawal of the full contract balance (SWC-105), `keccak256` mixed with block fields (SWC-120), timestamp comparisons (SWC-116), storage-array `.length` loops and storage writes inside loops (SWC-128), the 2300-gas `transfer` / `send` stipend (SWC-134), an unpinned pragma (SWC-103), deprecated syntax (SWC-111), and strict equality on `address(this).balance` (SWC-132).
- **CI exit codes and JSON.** `--format json` writes a machine-readable report (`summary`, per-file pragma class, findings). The process exits `1` when any finding meets `--fail-on` (default `high`, so critical and high fail the job) and `2` when no Solidity file was read.

### Production Environment Test Suite

The suite is `tests/test_audit.py`: 25 assertions, run with the standard library `unittest` runner.

- The bundled vulnerable vault must report SWC-107 on the `.call` line and SWC-101 on the later `-=`, and the related write line must be greater than the call line.
- A `.call` in contract A followed by `balances[...] -=` in contract B must not be reentrancy.
- Checks-effects-interactions, a `nonReentrant` modifier, and a lock release that is the only write after the call must stay silent. A balance update after that lock release must still fire.
- Comments, string literals, and a commented-out `pragma solidity ^0.7.6` above a real `0.8.20` pragma must not create a reentrancy or overflow finding.
- Same-file inheritance must still see the parent's `balances` mapping. A local variable that shadows `balances` must not.
- `tx.origin`, unchecked `.call`, `delegatecall`, unprotected `selfdestruct`, full-balance `transfer`, unbounded storage loops, ignored ERC-20 `transfer` returns, multiline `.call`, and `keccak256(block.timestamp)` each have a direct assertion.
- `examples/SafeVault.sol` (pinned `0.8.24`, effects before the call, `nonReentrant`) must produce an empty finding list.
- The CLI must exit `1` on the vulnerable sample, `0` with `--fail-on none`, and `2` when the path does not exist.
