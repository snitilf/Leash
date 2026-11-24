# Leash README demo. Re-record inside the repo's Linux dev environment
# (Leash only runs on Linux) with: vhs docs/assets/demo.tape
# Needs: vhs, ttyd, ffmpeg, the JetBrains Mono font, jq, and a release build
# of leash at /workspaces/Leash/target/release. /tmp/bg.png is a 1280x520
# diagonal pastel gradient (#8EC5FC to #E0C3FC) used as the window backdrop.
Output "/tmp/demo.gif"

Set Shell bash
Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1280
Set Height 520
Set Framerate 24
Set TypingSpeed 40ms
Set WindowBar Colorful
Set BorderRadius 10
Set Margin 40
Set MarginFill "/tmp/bg.png"
Set Padding 24

Hide
Type "export PATH=/workspaces/Leash/target/release:$PATH" Enter
Type "rm -rf /tmp/demo /tmp/demo-state && mkdir -p /tmp/demo/examples ~/.ssh && cd /tmp/demo" Enter
Type "cp /workspaces/Leash/examples/policy.toml examples/policy.toml" Enter
Type "echo fake > ~/.ssh/id_demo && chmod 600 ~/.ssh/id_demo" Enter
Type "export XDG_STATE_HOME=/tmp/demo-state" Enter
Type `F='select(.matched_rule=="fs.1" or .matched_rule=="fs.3") | {path: .fact.path, decision, ask_resolution, matched_rule}'` Enter
Type "R=/tmp/demo-state/leash/runs" Enter
Type "PS1='$ '" Enter
Type "clear" Enter
Sleep 500ms
Show

Sleep 1s
Type "# an agent tries to read an ssh key (policy: deny)" Enter
Sleep 800ms
Type "leash run --policy examples/policy.toml -- sh -c 'cat ~/.ssh/id_demo'" Sleep 500ms Enter
Sleep 4s

Type "clear" Enter
Type "# now it writes .env (policy: ask)" Enter
Sleep 800ms
Type "leash run --policy examples/policy.toml -- sh -c 'echo API_KEY=demo > .env; cat .env'" Sleep 500ms Enter
Wait+Screen@10s /allow\?/
Sleep 1500ms
Type "y"
Enter
Sleep 4s

Type "clear" Enter
Type "# every decision is in the report and the trace" Enter
Sleep 1s
Type `grep -h -E 'ssh|\.env' $R/*/report.txt` Sleep 500ms Enter
Sleep 3s
Type `jq -c "$F" $R/*/trace.jsonl` Sleep 500ms Enter
Sleep 5s
