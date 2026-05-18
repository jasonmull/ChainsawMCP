# Claude Code Prompts

Reusable prompts for consistent documentation and process improvement across sessions.

---

## End of Session

Use this at the end of every Claude Code session before closing out.

```
We're done for today. Before we close out, I need you to do three things:

1. Write any Architecture Decision Records from this session into `BUILD_LOG.md` using the ADR format in that file. If no firm architectural decisions were made, note what was explored and ruled out instead.

2. Add a session entry to `BUILD_LOG.md` summarizing:
   - What were the 2-3 most important decisions or findings from today?
   - What did we try that didn't work?
   - What should I know or watch out for going into the next session?

3. Based on how this session went, what specific additions or changes to `CLAUDE.md` would have made your guidance more effective? Write those suggestions as a comment block at the bottom of `CLAUDE.md`.
```

---

## Start of Session

Use this at the beginning of a new session to reorient Claude Code quickly.

```
Before we start, read BUILD_LOG.md and summarize:
- The most recent session entry
- Any open questions or watch-outs from last time
- The current ADR list so we don't re-litigate settled decisions
```

---

## When You're Stuck

Use this when a session has gone in circles or you've lost the thread.

```
Let's step back. Ignore the last [N] messages. What problem were we originally trying to solve, what approaches have we tried, and what's the simplest path forward from where we actually are?
```

---

## Talk/CFP Capture

Use this periodically (every few sessions) to mine the build log for presentation material.

```
Read BUILD_LOG.md and identify:
- The 3 most interesting decisions or trade-offs worth explaining to a practitioner audience
- The most instructive failure or dead end so far
- Any moment where the AI surprised you — positively or negatively
- A one-sentence "what I learned" for each of these

Format the output as bullet points I can drop into a slide outline.
```
