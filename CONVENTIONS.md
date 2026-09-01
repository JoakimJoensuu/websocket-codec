# Conventions

Do not restate language or protocol standards.

## Language

ISO C23, hosted. No extensions.

Cast only when there is no implicit conversion, and only when that is the
most readable way.

Parenthesize sizeof operands, even when the grammar allows omitting
them.

## Writing

Keep it short. Commit and PR titles too.

No em dashes.

Blank line between logical groups.

## Source of truth

Do not write the same fact in two places. One source of truth.
Tools and other files refer to it, or say nothing.

## Errors

Programming errors abort, expected failures still return an error.

## Names

In libraries, prefix only what is exposed.

Do not typedef structs or enums.

Size is how big an object is. Length is how long a sequence
is. Count is how many items.

```c
struct point {
  int x;
};

struct point points[] = {{.x = 0}, {.x = 1}};

int point_count = 2;
size_t point_size = sizeof(struct point);

int points_length = 2;
size_t points_size = 2 * sizeof(struct point);
```

Prefer full words over abbreviations, except the library prefix on exposed
names. Match the protocol's names when it has them.

The type is the kind of thing. The name is the role. Do not repeat the
type in the name.

## Functions

Do not use a boolean parameter to choose between two operations. Use two
functions. A flag on one operation is fine.

Pure functions that return a boolean are named as predicates. Other pure
functions are named as nouns.

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
one. Keep them up to date.
