# Conventions

Not language or protocol standards.

## Writing

Keep it short. Commit and PR titles too.

## Source of truth

Do not write the same fact in two places. One source of truth.
Tools and other files refer to it, or say nothing.

## Errors

Programming errors abort. Do not return an error code, and do not use
`assert` (that disappears under `NDEBUG`). Call `abort()`.

That includes NULL where a pointer is required, a positive length with a
NULL buffer, and any other caller-contract violation. A destroy function
is the exception: it accepts NULL, same as `free`.

Expected failures still return an error code: out of memory, and peer or
resource failures. Do not add an invalid-argument code.

## Functions

Do not use a boolean parameter to choose between two operations. Use two
functions. A flag on one operation is fine.

## Comments

Comment only what names, types, and control flow cannot say. When a public
declaration needs a comment, write it as a documentation comment on the
header, not on the `.c` definition.

## Tests

Assert observable behaviour through the public API, not internal
implementation.

## Commits and PRs

A title must complete "This commit/PR will …" with what the change
does to the files, not what those files do or say afterwards. Do not
end it with a period.

A body describes or reasons the change when that is needed. Otherwise
leave it empty. Do not repeat the changed lines.

An open PR's title and body describe the current diff, not an earlier
one. Update them when the files change.
