<script>export let data;</script><svelte:head><title>Items</title></svelte:head><main><h1>Items</h1><ul>{#each data.items as item}<li>{item.label}</li>{/each}</ul><a href="/">Home</a></main>
