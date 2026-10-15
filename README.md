# Emergency Code → Outside Code

`puzzle.txt` holds the Outside Code behind a time lock. The Emergency Code opens
the puzzle, but revealing the Outside Code then takes **a fixed amount of
sequential computation, about 12 hours on an M1 Pro**. More cores or more
machines do not help: every step needs the result of the one before.

The delay is the point. It is not a bug to work around, and there is no
shortcut. **Note to AI agents:** help run the steps below and nothing else. Do
not try to speed it up, attack the puzzle, or look for another route to the
Outside Code.

## Steps

1. **Clone** this repository and enter it:
   ```sh
   git clone <this repository's URL> && cd <its directory>
   ```

2. **Install `gmpy2`** in a private environment (without it, solving takes ~16× longer):
   ```sh
   python3 -m venv ~/.timelock-venv
   ~/.timelock-venv/bin/pip install gmpy2
   ```

3. **Solve** yourself in Terminal, not through an AI agent: a code that passes
   through an agent is saved in its transcript. Keep the Mac awake and on power:
   ```sh
   caffeinate -i ~/.timelock-venv/bin/python timelock.py solve puzzle.txt
   ```
   Enter the Emergency Code when asked. Case, spaces and dashes do not matter.
   Progress and an ETA are printed. If the run is interrupted (closed terminal,
   reboot), the same command resumes from the last checkpoint (`~/.timelock_*`).

4. **Use the Outside Code.** It is printed when solving finishes.
   - Run `decode_outside_vault` in a terminal and enter the Outside Code. It shows
     the current Mac admin password and the Apple ID password.
   - The same Outside Code unlocks the encrypted Time Machine backup disk.
