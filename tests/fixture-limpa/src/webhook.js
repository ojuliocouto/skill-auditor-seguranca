app.post("/api/webhook/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let evento;
  try {
    evento = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    return res.sendStatus(400);
  }
  if (evento.type === "checkout.session.completed") await liberarPlano(evento.data.object.customer);
  res.sendStatus(200);
});
