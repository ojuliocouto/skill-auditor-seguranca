import rateLimit from "express-rate-limit";
app.use(rateLimit({ windowMs: 60000, max: 100 }));
