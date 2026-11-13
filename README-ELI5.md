# Pullo, explained like you're five

**Pullo is a robot that reads code changes and points out mistakes. A second robot checks its homework before you see anything.**

## The story

Imagine your friend built a LEGO tower and changed a few bricks. You want to know whether they broke anything.

1. **Take a photo of the tower before and after the change.** 📸
   Pullo saves the exact "before" and "after" versions of the code, so nobody can secretly swap them later.

2. **Detective robot looks for problems.** 🕵️
   It reads what changed, then looks at the *other* bricks that touch the changed ones, because breaking a brick can make something on the other side of the tower fall over. It writes down guesses like "I think this brick is loose."

3. **Checker robot tries to prove the detective wrong.** 🔍
   For every guess, a second pass asks "show me exactly where." It has to point at real code it actually looked at. If it can't, the guess is thrown away.

4. **Judge robot writes the notes.** 📝
   The guesses that survived become short review comments, saved as files on your computer.

5. **You decide.** 🙋
   Pullo never changes the code, never runs it, and never posts anything online. It only gives you notes. Whether to fix anything is up to you.

## The safety rules

- 👀 **Look, don't touch.** The code being reviewed is only read, never run.
- 💰 **Pocket-money limit.** Each review has a hard spending cap ($4). Pullo stops when the money runs out, and there are no do-overs.
- 🧾 **It keeps a diary.** Every question it asks the AI and every file it opens is written down, so you can play the whole review back later and get the exact same answer without spending anything.
- 🧪 **Practice mode.** "Plan" mode shows exactly what it *would* send and the most it could cost, without sending anything.

## Is it good yet?

**Not proven yet.** Pullo is very early (pre-alpha). So far it has shown that all the steps *work*: once, it found a bug that was planted on purpose, checked it and wrote a comment. Nobody has measured yet how often it catches real bugs or how often it is wrong.

## Try it (no money, no internet)

```sh
python3 -m reviewer smoke record --out /tmp/smoke-rec
```

This runs pretend reviews with a scripted fake AI, just to check that the machine works. You need Python 3.14.

---

Want the grown-up version? Read [README.md](README.md).
