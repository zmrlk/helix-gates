export function Form() { return <section>
<label htmlFor="email">Email</label><input id="email" />
<label>Name <input /></label>
<input aria-label="Search" />
<input type="hidden" /><input type="submit" value="Save" />
<img src="decorative.png" alt="" />
<button onClick={() => act()}>Save</button>
<div role="button" tabIndex={0} onKeyDown={key} onClick={save}>Save</div>
</section>; }
