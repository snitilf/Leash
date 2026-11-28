# Leash README demo. Re-record inside the repo's Linux dev environment
# (Leash only runs on Linux) with: vhs docs/assets/demo.tape
# Needs: vhs, ttyd, ffmpeg, the JetBrains Mono font, jq, and a release build
# of leash at /workspaces/Leash/target/release. /tmp/bg.png is a 1280x520
# diagonal pastel gradient (#8EC5FC to #E0C3FC) used as the window backdrop.
# The --snapshots segment needs a delegated cgroup v2, and vhs must start
# inside it, so its child shell inherits it. In a codespace:
#   sudo mkdir /sys/fs/cgroup/leash-demo && sudo chown -R "$USER" /sys/fs/cgroup/leash-demo
#   echo $$ | sudo tee /sys/fs/cgroup/leash-demo/cgroup.procs
#   vhs docs/assets/demo.tape
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
Type "rm -rf /tmp/demo /tmp/demo-state && mkdir -p /tmp/demo/examples /tmp/demo/src ~/.ssh && cd /tmp/demo" Enter
Type "cp /workspaces/Leash/examples/policy.toml examples/policy.toml" Enter
Type "echo fake > ~/.ssh/id_demo && chmod 600 ~/.ssh/id_demo" Enter
Type "echo 'fn main() {}' > src/main.rs && echo 'old notes' > notes.txt" Enter
Type "export XDG_STATE_HOME=/tmp/demo-state" Enter
Type `F='select(.matched_rule=="fs.1" or .matched_rule=="fs.3") | {path: .fact.path, decision, ask_resolution, matched_rule}'` Enter
Type "R=/tmp/demo-state/leash/runs" Enter
# A snapshot run keeps a copy of its stderr, and undo runs the command that
# leash printed, so the tape never has to type a run id or a digest.
Type `leash() { if [[ " $* " == *" --snapshots "* ]]; then command leash "$@" 2> >(tee /tmp/demo-err >&2); wait $!; else command leash "$@"; fi; }` Enter
Type `undo() { eval "$(sed -n 's/^leash: to undo this run: //p' /tmp/demo-err | tail -1)"; }` Enter
Type "PS1='$ '" Enter
Type "clear" Enter
Sleep 500ms
Show

Sleep 500ms
Type "# an agent tries to read an ssh key (policy: deny)" Enter
Sleep 500ms
Type "leash run --policy examples/policy.toml -- sh -c 'cat ~/.ssh/id_demo'" Sleep 400ms Enter
Sleep 2500ms

Type "clear" Enter
Type "# now it writes .env (policy: ask)" Enter
Sleep 500ms
Type "leash run --policy examples/policy.toml -- sh -c 'echo API_KEY=demo > .env; cat .env'" Sleep 400ms Enter
Wait+Screen@10s /allow\?/
Sleep 1s
Type "y"
Enter
Sleep 2500ms

Type "clear" Enter
Type "# every decision is in the report and the trace" Enter
Sleep 500ms
Type `grep -h -E 'ssh|\.env' $R/*/report.txt` Sleep 400ms Enter
Sleep 2s
Type `jq -c "$F" $R/*/trace.jsonl` Sleep 400ms Enter
Sleep 3500ms

Hide
Type "rm -f .env && clear" Enter
Show
Type "# --snapshots: leash can put the workspace back" Enter
Sleep 500ms
Type "ls" Enter
Sleep 800ms
Type "leash run --snapshots --policy examples/policy.toml -- sh -c 'echo wip >> src/main.rs; rm notes.txt'" Sleep 400ms Enter
Wait+Screen@15s /to undo this run/
Sleep 3500ms

Type "clear" Enter
Type "# the agent edited a file and deleted another: rewind with the printed command" Enter
Sleep 500ms
Type "undo" Sleep 400ms Enter
Wait+Screen@15s /rewind reverses/
Sleep 3500ms

Type "clear" Enter
Type "ls; cat notes.txt src/main.rs" Sleep 400ms Enter
Sleep 4s
