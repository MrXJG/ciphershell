# Domain Docs

This repo uses a single-context layout for Matt Pocock engineering skills.

## Before Exploring, Read These If Present

- `CONTEXT.md` at the repo root
- Relevant ADRs under `docs/adr/`
- Existing project guidance in `AGENTS.md`
- Existing compatibility notes under `docs/`

If these files do not exist, proceed silently. Do not create domain docs upfront just because they are missing. Producer skills such as `grill-with-docs` can create or update them when real terminology or decisions are resolved.

## File Structure

```text
/
├── CONTEXT.md
├── docs/
│   ├── adr/
│   └── agents/
└── src/
```

## Vocabulary Rule

When output names a project concept, use the language already present in `CONTEXT.md`, `AGENTS.md`, and `docs/`. For this project, terms like `国密`, `旧版国密适配`, `modern 引擎`, `legacy 引擎`, `麒麟 SP3 2403`, and `openEuler 纯国密` should stay consistent.

## ADR Conflicts

If a recommendation contradicts an existing ADR or compatibility matrix, surface the conflict explicitly instead of silently overriding it.
