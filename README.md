# auditor-seguranca

Security and LGPD (Brazilian data protection law) auditor for projects built with AI assistance.
A Claude Code skill that **runs** on the project and reports what is exposed, instead of handing
the user a passive checklist. Built for people who have never been developers.

## What it is

- An executable gate: `scripts/varredura.py` scans the project and exits **red** (code 2) on any
  critical finding, so "done" cannot be declared over an exposed secret.
- A guided flow: the skill instructs the AI agent to explain every finding in plain language
  (each one has a ready-made lay explanation with an analogy in
  `references/achados-explicados.md`), fix it together with the user, and re-run until green.
- A deploy check: `scripts/checar_deploy.py` tests a **published** site for publicly accessible
  `.env` / `.git` files and missing security headers. GET requests only.

## What it is NOT

- Not a pentest. It reads code at rest and knocks on the front door of a site. It does not test
  authorization logic and it does not attack anything.
- Not legal advice. LGPD guidance here is technical; legal calls (lawful basis, public sector,
  sensitive data) belong to a lawyer/DPO, and the skill says so explicitly.
- A clean scan means "this scan found nothing", never "the project is secure". The skill is
  instructed to say exactly that.

## What the scanner catches

| Finding | Severity |
|---|---|
| API keys / tokens / private keys hardcoded (OpenAI, Groq, Google, GitHub, AWS, Stripe, Slack, Notion, JWT, passwords) | CRITICAL |
| `.env` tracked by git, or present anywhere in git **history** | CRITICAL |
| Supabase `service_role` key in frontend code | CRITICAL |
| `.gitignore` not ignoring `.env` | HIGH |
| Personal data (CPF, email, phone, password fields) being logged | HIGH |
| Literal CPF (Brazilian ID) in code | HIGH |
| CORS open to `*` | MEDIUM |
| Admin page with no sign of authentication (heuristic) | VERIFY |
| Supabase in use → RLS must be checked (ready-made read-only SQL included) | VERIFY |

Secret values are always masked in output. The scan never modifies any file.

## Prerequisites

- **Python 3.9+** (standard library only, no pip install needed)
- **git** (optional: without it the history checks are skipped and the report says so)
- [Claude Code](https://claude.com/claude-code) or any agent that reads `SKILL.md`

## Install

```bash
git clone https://github.com/ojuliocouto/skill-auditor-seguranca.git ~/.claude/skills/auditor-seguranca
```

Then, inside Claude Code: `/auditar-seguranca` (or just ask "meu projeto está seguro?").

First use: the skill checks your environment (`python3 --version && git --version`) and guides
you from there. No accounts, no API keys, no network access except the optional deploy check
against your own site.

## Standalone usage (no AI agent)

```bash
python3 scripts/varredura.py /path/to/your/project        # scan code, exit 2/1/0
python3 scripts/checar_deploy.py https://your-site.com    # check published site
```

## Contents

```
SKILL.md                     agent playbook: flow, conduct rules, honest limits
scripts/varredura.py         the scanner (the gate)
scripts/checar_deploy.py     published-site check
references/achados-explicados.md   every finding explained for non-developers
references/rls-consulta.sql        read-only SQL to list Supabase tables without RLS
references/SECURITY_*.md           knowledge base (see Credits)
tests/                       proof the gate works both ways (see Security note)
```

## Security note about the test fixtures

`tests/fixture-vulneravel/` contains **planted, fake, non-functional secrets** (realistic format,
invented content). They exist so the test suite can prove the gate goes red when it must:
`tests/test_varredura.py` asserts 8 specific findings on the vulnerable fixture and zero on the
clean one. None of those strings is or ever was a real credential. If your secret scanner flags
this directory, that is the fixture doing its job.

```bash
python3 tests/test_varredura.py   # expected: 10/10
```

## Sources

The knowledge base in `references/` (AI security instructions, a 326-item checklist across 8
phases and a 48-section playbook) consolidates public security references: NIST SSDF,
NIST SP 800-218A and Lei 13.709/2018 (LGPD).

## License

MIT — see [LICENSE](LICENSE).
