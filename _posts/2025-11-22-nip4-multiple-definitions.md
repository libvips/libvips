---
title: Multiple definitions in nip4 
---

There's a [new nip4 release, v9.0.15,](https://github.com/jcupitt/nip4/releases)
with some useful improvements to nip4's programming language. I thought I'd
write a summary of this new feature.

For some background, there's an older [introduction to
nip4](/2025/03/20/introduction-to-nip4.html) post.

## nip4's programming language

nip4 is an image processing spreadsheet and, like all spreadsheets, you can
type equations into cells. 

The equations you can type are in fact a tiny pure functional programming
language, and this language is used to implement all of nip4's menus and
workspace widgets.  You can use it to add things to nip4 yourself. 

One way to experiment with it is with the **Workspace definitions** pane.
If you right-click on the workspace background and pick Workspace definitions
from the menu, a pane will slide in from the right:

![nip4](/assets/images/nip4-wsdefs.png)

This pane holds definitions local to this workspace tab. They are saved in the
workspace file, so they are a great way to add small extra things that are
useful for whatever you are working on.

Try entering:

```
fred = 99;
```

Pressing the ▶ (play) button will make nip4 parse and compile your
definition.  Back in the workspace, try entering `fred` at the bottom of
column `A`. You should see:

![nip4](/assets/images/nip4-wsdefs2.png)

If you go back to the Workspace definitions pane, edit it to `fred =
"banana";`, and press ▶ again, `A1` will update. Definitions are all live
and if you change one, everything that uses it will also update.

If you right-click on the workspace background and select **Edit toolkits**
you'll get something more like a tiny development environment for the
language, but **Workspace definitions** is handier for little experiments.

## Multiple definitions

The big new feature in this new version is multiple definitions. You can 
define a function many times and during execution the first one which matches 
the arguments becomes the result of the function.

For example, you could write this to define a factorial function:

```
factorial 1 = 1;
factorial n = n * factorial (n - 1);
```

Now `factorial 6` in a column will evaluate to 720.

This is not a great way to write a factorial function! But it does show the
syntax. Something like:

```
factorial n = product [1..n];
```

would be better.

## Deconstruction

A parallel new feature is function argument pattern matching and 
deconstruction. 

Function arguments don't have to be simple variables --- they can be
complex structure declarations. For example:

```
sum [] = 0;
sum a:x = a + sum x;
```

Square brackets mean lists and the colon (`:`) operator is infix CONS. The
first definition of `sum` will match if the argument is the empty list, and
the second for non-empty lists (lists which can be deconstructed with CONS),
with `a` being bound to the head of the list and `x` to the tail.

Back in the workspace, `sum [1..10]` should be 55. The `[1..10]` is a list
generator, it evaluates to `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]`.

This is a pretty bad way to define `sum`, a better solution is:

```
sum = foldr add 0
```

Where foldr is the standard right-associative list fold operator. You can
define it very conveniently as:

```
foldr fn st [] = st;
foldr fn st x:xs = fn x (foldr fn st xs);
```

## Other pattern matching features

Patterns can be simple constants, complex numbers, list constants, `:` (cons),
classes and argument names. You can nest these in any way you like, so:

```
conj (x, y) = (x, -y);
```

Finds the complex conjugate, or:

```
banana [a, (x, y), c] = "a three element list, with a complex number as the middle element";
```

Or:

```
test (Image x) = "it's an image!";
```

This matches any `x` which is an instance of the `Image` class.

## Next

The next step is to update the nip4 menus, hopefully making them more
consistent and easier to use. We'll see!
