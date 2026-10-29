app.post("/api/cadastro", async (req, res) => {
  const hash = await bcrypt.hash(req.body.senha, 12);
  await prisma.usuario.create({ data: { nome: req.body.nome, senha: hash } });
  res.sendStatus(201);
});
app.get("/api/pedidos/:id", async (req, res) => {
  const r = await db.query("SELECT * FROM pedidos WHERE id = $1", [req.params.id]);
  const t = await sql`SELECT * FROM itens WHERE pedido = ${req.params.id}`;
  res.json(r.rows);
});
