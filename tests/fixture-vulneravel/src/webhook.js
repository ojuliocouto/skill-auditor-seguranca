// fixture: webhook de pagamento que libera plano sem validar a assinatura
app.post("/api/webhook/stripe", async (req, res) => {
  const evento = req.body;
  if (evento.type === "checkout.session.completed") await liberarPlano(evento.data.object.customer);
  res.sendStatus(200);
});
