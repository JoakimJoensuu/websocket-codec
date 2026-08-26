# Conventions

Do not restate language or protocol standards.

## Language

ISO C23, hosted. No extensions.

## Writing

Keep it short. Commit and PR titles too.

## Source of truth

Do not write the same fact in two places. One source of truth.
Tools and other files refer to it, or say nothing.

## Errors

Programming errors abort, expected failures still return an error.

## Names

In libraries, prefix only what is exposed.

Do not typedef structs or enums.

Use `_cnt` for item counts and `_len` for sequence length.

Prefer full words over abbreviations. Match the protocol's names when it has them.

## Functions

Do not use a boolean parameter to choose between two operations. Use two
functions. A flag on one operation is fine.

## Comments

Comment only what names, types, and control flow cannot say. When a public
declaration needs a comment, write it there in Doxygen style, not on the
definition.

## Tests

Assert observable behaviour through the public API, not internal
implementation.

## Commits and PRs

A title must complete "This commit/PR will …" with what the change
does to the files, not what those files do or say afterwards. Do not
end it with a period.

A body describes or reasons the change when that is needed. Otherwise
leave it empty.

An open PR's title and body describe the current diff, not an earlier
one. Update them when the files change.
