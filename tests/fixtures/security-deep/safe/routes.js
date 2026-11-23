router.get('/items/:id', requireAuth(), (req, res) => {
 return db.items.findFirst({where: {id: req.params.id, ownerId: session.user.id}});
});
router.post('/items', requireRole('admin'), (req, res) => {
 return db.query('SELECT * FROM items WHERE id=$1 AND owner_id=$2', [req.params.id, session.user.id]);
});
