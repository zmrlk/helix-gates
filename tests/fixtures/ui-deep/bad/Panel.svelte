<script>const items = fetch('/items');</script>
<input placeholder="Nazwa">
<img src="banner.png">
<div on:click={save}>Zapisz</div>
<button class="danger" on:click={remove}>Usuń</button>
<button>Cancel</button>
<p>Lorem ipsum TODO</p>
{#each items as item}<span>{item.name}</span>{/each}
<style>.panel { padding: 13px; border-radius: 7px; font-size: 13px; color: #123; }
button { outline: none; }</style>
