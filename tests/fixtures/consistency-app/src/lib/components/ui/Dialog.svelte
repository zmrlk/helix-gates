<script lang="ts">let { open = false, children } = $props();</script>
{#if open}<div class="fixed inset-0 z-50 bg-black/40" role="dialog" aria-modal="true">{@render children?.()}</div>{/if}
