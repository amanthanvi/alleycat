# Find an existing `codex` binary on the remote and emit "codex:<path>".
# Resolution preserves the caller's PATH order, then checks the fixed trusted
# locations supplied through SHARED_LINES. It never sources profile files,
# invokes package managers, or executes a candidate during detection.
_remora_first_selector=""
_remora_first_path=""

_remora_consider_candidate() {
  _remora_selector="$1"
  _remora_path="$2"
  if [ -n "$_remora_path" ] && [ -f "$_remora_path" ] && [ -x "$_remora_path" ]; then
    if [ -z "$_remora_first_path" ]; then
      _remora_first_selector="$_remora_selector"
      _remora_first_path="$_remora_path"
    fi
  fi
}
_remora_consider_from_dir() {
  _remora_selector="$1"
  _remora_name="$2"
  _remora_dir="$3"
  if [ -n "$_remora_dir" ]; then
    _remora_consider_candidate "$_remora_selector" "$_remora_dir/$_remora_name"
  fi
}
_remora_consider_path_candidates() {
  _remora_selector="$1"
  _remora_name="$2"
  _remora_old_ifs="$IFS"
  IFS=:
  for _remora_dir in $PATH; do
    if [ -n "$_remora_dir" ]; then
      _remora_consider_candidate "$_remora_selector" "$_remora_dir/$_remora_name"
    fi
  done
  IFS="$_remora_old_ifs"
}
{{SHARED_LINES}}
if [ -n "$_remora_first_path" ]; then
  printf '%s:%s' "$_remora_first_selector" "$_remora_first_path"
  exit 0
fi
