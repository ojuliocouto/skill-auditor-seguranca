// fixture: senha gravada sem hash e SQL montado com interpolacao
app.post("/api/cadastro", async (req, res) => {
  await prisma.usuario.create({ data: { nome: req.body.nome, senha: req.body.senha } });
  res.sendStatus(201);
});
app.get("/api/pedidos/:id", async (req, res) => {
  const r = await db.query(`SELECT * FROM pedidos WHERE id = ${req.params.id}`);
  res.json(r.rows);
});
