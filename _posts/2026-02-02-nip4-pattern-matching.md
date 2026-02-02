---
title: Patterns everywhere in nip4
---

January's work on nip4 [is out: 
v9.0.16](https://github.com/jcupitt/nip4/releases) has more useful improvements
to the programming language, with a few more minor changes.

This marks the end of work on nip4's language. Next month will focus on the
menu redesign.

For some background, there's an older [introduction to nip4's programming
language](/2025/11/22/nip4-multiple-definitions.html) post.

## More difficult row drag

Left-drag on the workspace background to scroll is very handy, but left-drag
also moved rows around. I found myself often dragging rows accidentally while
navigating large workspaces, and then putting the rows back in the right place
was annoying.

You now have to hold down CTRL to drag rows around. Hopefully this will stop
accidental row moves!

## Patterns everywhere!

I've rewritten lambda expressions so they now support patterns and
deconstruction. For example:

```
main = map (\[x, y] x + y) (zip2 [1..10] [11..20]);
```

So the lambda (the backslash character) expects a two element list with
elements named as `x` and `y` and adds them together. The `zip2` makes
a list like `[[1, 11], [2, 12], ..]`, so therefore `main` will have the
value `[12, 14, 16, ..]`.

This means that (finally!) you can use patterns and argument deconstruction
everywhere. For example, you could write that lambda expression as:

```
main = [x + y :: [x, y] <- zip2 [1..10] [11..20]];
```

I've also rewritten list comprehensions so they have much better scoping
behaviour. 

The compiler is now lazy -- everything is parsed during load, but code
generation only happens when functions are evaluated. This improves startup
time.

## It's now **snip**

And finally the programming language is officially renamed as **snip**, and
the old `nip54-batch` program is now installed as `snip`. You can use it to
write scripts with a shebang, perhaps:

```
#!/usr/bin/env snip

main = [x + y :: [x, y] <- zip2 [1..10] [11..20]];
```

You can run this and see:

```
$ ./try.def 
[12, 14, 16, 18, 20, 22, 24, 26, 28, 30]
$ 
```

... though that's not quite correct, for now you need a `print` in there too,
but this will be going away in the next version. 
