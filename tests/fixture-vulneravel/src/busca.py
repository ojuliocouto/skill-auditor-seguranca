def busca_usuario(cur, email):
    cur.execute(f"SELECT * FROM usuarios WHERE email = '{email}'")
