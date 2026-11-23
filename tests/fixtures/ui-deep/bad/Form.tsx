export function Form() { return <section>
<input placeholder="Email" />
<img src="photo.png" />
<div onClick={() => act()}>Save</div>
<button className="danger" onClick={remove}>Delete</button>
</section>; }
