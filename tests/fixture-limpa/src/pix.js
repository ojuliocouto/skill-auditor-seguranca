// webhook protegido por segredo no caminho da URL
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === "POST" && url.pathname === `/webhook/${env.WEBHOOK_SEGREDO}`) return processa(await req.json());
    return new Response("nao encontrado", { status: 404 });
  },
};
