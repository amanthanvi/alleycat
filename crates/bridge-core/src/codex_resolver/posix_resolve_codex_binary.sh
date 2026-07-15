# Find an existing `codex` binary on the remote and emit "codex:<path>".
# Resolution preserves the caller's PATH order, then checks the fixed trusted
# locations supplied through SHARED_LINES. It never sources profile files,
# invokes package managers, or executes a candidate during detection.
_litter_first_selector=""
_litter_first_path=""

_litter_consider_candidate() {
  _litter_selector="$1"
  _litter_path="$2"
  if [ -n "$_litter_path" ] && [ -f "$_litter_path" ] && [ -x "$_litter_path" ]; then
    if [ -z "$_litter_first_path" ]; then
      _litter_first_selector="$_litter_selector"
      _litter_first_path="$_litter_path"
    fi
  fi
}
_litter_consider_from_dir() {
  _litter_selector="$1"
  _litter_name="$2"
  _litter_dir="$3"
  if [ -n "$_litter_dir" ]; then
    _litter_consider_candidate "$_litter_selector" "$_litter_dir/$_litter_name"
  fi
}
_litter_consider_path_candidates() {
  _litter_selector="$1"
  _litter_name="$2"
  _litter_old_ifs="$IFS"
  IFS=:
  for _litter_dir in $PATH; do
    if [ -n "$_litter_dir" ]; then
      _litter_consider_candidate "$_litter_selector" "$_litter_dir/$_litter_name"
    fi
  done
  IFS="$_litter_old_ifs"
}
{{SHARED_LINES}}
if [ -n "$_litter_first_path" ]; then
  printf '%s:%s' "$_litter_first_selector" "$_litter_first_path"
  exit 0
fi
