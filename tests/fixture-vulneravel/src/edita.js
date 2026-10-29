await db.prepare(`UPDATE perfis SET nome = '${req.body.nome}' WHERE id = ?`).bind(id).run();
