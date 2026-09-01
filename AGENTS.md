# Agents

## Documentation and configs

Read and follow:
- [CONVENTIONS.md](CONVENTIONS.md)
- [.clang-format](.clang-format)
- [.clang-tidy](.clang-tidy)
- [README.md](README.md)

They apply to the files and commits you write, and to how you work in this
codebase. If a change goes against what they say, say so; if it is meant to
stand, propose the replacement.

If a request or suggestion goes against a common idiom or convention, say
so and keep the idiom. Do that even when they ask directly. Change it only
after they confirm they want the exception.

When the user's input states or implies a standing practice, propose how
we write it, in wording another repository could reuse. A correction counts
when it is how that kind of thing should always be done. One instance
is enough to propose.

The same applies when the task itself reveals a gap: if you had to follow
a practice that README, CONVENTIONS, or AGENTS does not yet say, propose
an update. Do not wait for the user to ask. Put commands in README,
maintainer rules in CONVENTIONS, agent workflow in AGENTS.

### Proposing a change

Every change to these documents needs approval first: a new convention, a
replacement, a document added to the list, a link that no longer points
anywhere. Do not wait for an answer. Finish the task, then put the
proposal last in your reply under the heading "Proposed", so it is easy
to find and quote. Name the file and quote the wording. Do not edit until
it is accepted; a direct request already counts.

An agent-suggested change that is not the current task goes on a
new branch.

### Contradictions in existing files

If something existing contradicts a convention, the existing thing is
wrong. Do not change the convention to match. Propose a fix as described
above. If files contradict themselves or each other, flag that too.

## After changes to source code

Run and pass any checks described in documentation or configs.

## Commits and pull requests

Do not attribute a commit or pull request to a tool or agent.

After pushing to a branch with an open pull request, ask whether to update
the title and body to match the current diff. Do not update them without
confirmation unless the user asked.
