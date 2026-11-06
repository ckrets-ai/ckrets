# Security policy

## Reporting a vulnerability

Please report it privately: use **"Report a vulnerability"** on this repository's **Security** tab
(https://github.com/ckrets-ai/ckrets/security/advisories/new). If you can't use GitHub, write to admin@ckrets.ai.
Don't open a public issue, and don't include real secrets in a report: describe the steps, or use test values.

## Scope

- **In scope:** the clients in this repository (`@ckrets/helper`, `@ckrets/mcp`, the `ckrets` Python package and the
  MCP registry entry), and the ckrets.ai service they talk to (the API at `https://ckrets.ai/v1`, the MCP server at
  `https://ckrets.ai/mcp`, and the reveal and request pages). How the service handles your values, and what ckrets can
  and can't read, is at https://ckrets.ai/docs/trust.
- **Out of scope:** denial of service and load testing against ckrets.ai, social engineering, and reports that only
  restate a documented limit (https://ckrets.ai/docs/limits).

## What to expect

- We acknowledge a report within **3 working days**, and tell you what we will do and roughly when.
- We fix confirmed issues in this repository and on the service, publish a GitHub security advisory for the clients
  when users need to act, and credit you if you want to be named.
- There is **no bug bounty** yet.

## Supported versions

ckrets is in beta (0.9.x). Fixes go into the latest 0.9 release; upgrade to it.
