"""Shared exclusions for private agent state, including nested worktree copies."""

# These are tool-owned state directories, not application components. Keep the
# policy independent of project names and use it in filesystem and Git readers.
AGENT_STATE_DIRECTORIES = frozenset({'.claude', '.codex', '.agents'})
