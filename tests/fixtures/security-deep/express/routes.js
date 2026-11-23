router.get('/items/:id', (req, res) => {
 return db.items.findUnique({where: {id: req.params.id}});
});
router.post('/exec', (req, res) => {
 exec(req.body.command);
 readFile(req.query.path);
 db.query(`SELECT * FROM items WHERE id=${req.query.id}`);
 const role = body.role;
 const isAdmin = true;
 if (process.env.SKIP_AUTH) return;
 upload(req);
 const otp = Math.random() == input;
 return req.get('host');
});
