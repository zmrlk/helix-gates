<script lang="ts">import Button from '$lib/components/ui/Button.svelte'; let show = $state(false);</script>
<h1 class="text-2xl font-bold">Moje zamówienia</h1>
<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-amber-100 text-amber-800">Oczekuje</span>
<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-green-100 text-green-800">Potwierdzone</span>
{#if show}<div class="fixed inset-0 z-40 grid place-items-center bg-black/50" role="dialog"><div class="rounded-lg bg-white p-4">Podgląd</div></div>{/if}
<Button>Zapisz</Button>
