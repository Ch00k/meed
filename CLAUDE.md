# meed

Emails new RSS/Atom feed entries. One module, `meed.py`, run roughly hourly as a scheduled Fly.io Machine.

## Stage

`0.x.y` - beta: in production for its owner. The feed list (`feeds.txt`) and the state (`state.json`) live in a Tigris
bucket and must survive every change, so a change to the state JSON format needs a migration.

## Decisions

- Deployment, releases and configuration: `README.md`. Why a release replaces the scheduled Machine instead of updating
  it, and the checks around that: the comments in `.github/workflows/ci.yml`.
- Repository: <https://github.com/Ch00k/meed>, public.
