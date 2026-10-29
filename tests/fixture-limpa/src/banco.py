def busca(self, tabela, id):
    return self.um(f'SELECT * FROM {tabela} WHERE id = ?', (id,))

def insere(self, tabela, nomes, valores):
    sql = f'INSERT INTO {tabela} ({", ".join(nomes)}) VALUES ({", ".join("?" for _ in nomes)})'
    self.con.execute(sql, valores)

def resumo(p, pend):
    return f'Avisos na fila: {pend}. Pendentes: {p.banco.um("SELECT COUNT(*) AS n FROM fila WHERE feito_em IS NULL")["n"]}.'

def ultima(cur, marcas, espec):
    return cur.execute(
        f'SELECT id, em FROM acao_ig WHERE acao IN ({marcas}) ORDER BY em DESC LIMIT 1', espec['grupo'])
