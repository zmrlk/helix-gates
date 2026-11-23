<script lang="ts">import Button from '$lib/components/ui/Button.svelte'; let open = $state(false); let items = [];</script>
<h1 class="text-2xl font-bold">Zamówienia</h1>
<button class="px-3 py-1 rounded-md bg-black text-white" onclick={() => (open = true)}>Szczegóły</button>
<button class="px-3 py-1 rounded-md text-[13px]">Zapisz</button>
<button class="px-3 py-1 rounded-md" style="color:#ff0000">Usuń</button>
<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-amber-100 text-amber-800">Oczekuje</span>
{#if open}
<div class="fixed inset-0 z-50 flex justify-end bg-black/30" role="dialog" aria-modal="true">
  <div class="h-full w-[420px] bg-white p-6 shadow-xl"><h2 class="text-lg font-semibold">Zamówienie</h2></div>
</div>
{/if}
<Button variant="secondary">Eksport</Button>
