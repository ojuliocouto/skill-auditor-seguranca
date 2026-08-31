#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prova o gate nos dois sentidos: VERMELHO na fixture vulneravel, verde na limpa."""
import json
import os
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(AQUI, "..", "scripts", "varredura.py")

def roda(fixture):
    """Copia a fixture pra um tmpdir e cria o git ali (fixture versionada nao pode ter .git
    proprio: viraria gitlink e sumiria no clone do repo da skill)."""
    import shutil, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        destino = os.path.join(tmp, fixture)
        shutil.copytree(os.path.join(AQUI, fixture), destino)
        g = ["git", "-C", destino, "-c", "user.email=t@t", "-c", "user.name=t"]
        subprocess.run(g + ["init", "-q"], check=True, timeout=60)
        subprocess.run(g + ["add", "-A"], check=True, timeout=60)
        subprocess.run(g + ["commit", "-qm", "fixture"], check=True, timeout=60)
        r = subprocess.run([sys.executable, SCRIPT, destino, "--json"],
                           capture_output=True, text=True, timeout=120)
    return r.returncode, json.loads(r.stdout)

falhas = []
def confere(nome, cond):
    print(("ok " if cond else "FALHOU ") + nome)
    if not cond:
        falhas.append(nome)

rc, d = roda("fixture-vulneravel")
codigos = {a["codigo"] for a in d["achados"]}
confere("vulneravel: gate sai vermelho (exit 2)", rc == 2)
confere("vulneravel: acha segredo no codigo", "SEGREDO_NO_CODIGO" in codigos)
confere("vulneravel: acha .env commitado", "ENV_COMMITADO" in codigos)
confere("vulneravel: acha service_role no frontend", "SERVICE_ROLE_NO_FRONTEND" in codigos)
confere("vulneravel: acha dado pessoal em log", "DADO_PESSOAL_EM_LOG" in codigos)
confere("vulneravel: acha CORS aberto", "CORS_ABERTO" in codigos)
confere("vulneravel: acha admin sem sinal de auth", "ADMIN_SEM_SINAL_DE_AUTH" in codigos)
confere("vulneravel: acha .gitignore sem .env", "GITIGNORE_SEM_ENV" in codigos)

rc2, d2 = roda("fixture-limpa")
confere("limpa: gate sai verde (exit 0)", rc2 == 0)
confere("limpa: zero achados", len(d2["achados"]) == 0)

print(f"\n{10 - len(falhas)}/10")
sys.exit(1 if falhas else 0)
