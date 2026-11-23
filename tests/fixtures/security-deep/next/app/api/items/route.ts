export async function POST(req) {
 const data = await db.items.update(req.body);
 return redirect(req.query.next);
}
