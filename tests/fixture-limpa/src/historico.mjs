// nome de tabela e lista de ? montados no codigo; os valores vao separados (seguro)
const marcas = ids.map(() => "?").join(", ");
await env.DB.prepare(`DELETE FROM ${TABELA} WHERE dashboard_id = ? AND dia IN (${marcas})`).bind(id, ...ids).run();
const r1 = await env.DB.prepare(`SELECT id FROM acoes WHERE id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all();
const r2 = await env.DB.prepare(`SELECT id, captured_at FROM ${TABLE} ` +
  `WHERE dashboard_id = ? ORDER BY id DESC`).bind(id).all();
const r3 = await linhas(`SELECT status FROM eventos WHERE id = ${Number(id)}`);
