<script>let loading, error; const response = fetch('/items').catch(handleError);</script>
<label for="name">Name</label><input id="name">
<img src="x" alt="Description">
{#if loading}<p>Loading</p>{:else if error}<p>Error</p>{/if}
{#each items as item}<p>{item}</p>{:else}<p>Empty</p>{/each}
<button on:click={() => confirm('Delete?') && remove()}>Delete</button>
