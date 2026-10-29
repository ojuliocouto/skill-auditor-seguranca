// fixture: segredo em variavel que o bundler publica no navegador
const stripe = new Stripe(process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY);
