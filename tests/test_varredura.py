#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prova o gate nos dois sentidos: VERMELHO na fixture vulneravel, verde na limpa."""
import json
import os
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(AQUI, "..", "scripts", "varredura.py")

def roda(fixture, path=None):
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
        # duble do npm na frente do PATH: o teste do npm audit nao depende de rede
        env = dict(os.environ, PATH=path or (os.path.join(AQUI, "duble-npm") + os.pathsep + os.environ["PATH"]))
        r = subprocess.run([sys.executable, SCRIPT, destino, "--json"],
                           capture_output=True, text=True, timeout=120, env=env)
    return r.returncode, json.loads(r.stdout)

falhas = []
TOTAL_CONFERENCIAS = [0]
def confere(nome, cond):
    TOTAL_CONFERENCIAS[0] += 1
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
# regras novas (29/10/2026), uma por item do checklist
confere("vulneravel: acha webhook sem assinatura", "WEBHOOK_SEM_ASSINATURA" in codigos)
confere("vulneravel: acha segredo em variavel publica (NEXT_PUBLIC_/VITE_)", "SEGREDO_EM_VAR_PUBLICA" in codigos)
publicas = {a["arquivo"] for a in d["achados"] if a["codigo"] == "SEGREDO_EM_VAR_PUBLICA"}
confere("vulneravel: var publica achada no codigo E no .env", {"src/pagamento.js", ".env"} <= publicas)
confere("vulneravel: acha senha gravada sem hash", "SENHA_SEM_HASH" in codigos)
confere("vulneravel: acha SQL montado com interpolacao", "SQL_CONCATENADO" in codigos)
confere("vulneravel: acha innerHTML com dado", "HTML_INSEGURO" in codigos)
sqls = {a["arquivo"] for a in d["achados"] if a["codigo"] == "SQL_CONCATENADO"}
confere("vulneravel: SQL em f-string do Python sem placeholder", "src/busca.py" in sqls)
confere("vulneravel: SQL com ? mas interpolando req.body", "src/edita.js" in sqls)
confere("vulneravel: acha API sem rate limit", "SEM_RATE_LIMIT" in codigos)
confere("vulneravel: acha dependencia vulneravel (npm audit)", "DEPENDENCIA_VULNERAVEL" in codigos)
dep = [a for a in d["achados"] if a["codigo"] == "DEPENDENCIA_VULNERAVEL"]
confere("vulneravel: npm audit reporta 1 critica e 2 altas", bool(dep) and "1 critica" in dep[0]["detalhe"] and "2 alta" in dep[0]["detalhe"])

rc2, d2 = roda("fixture-limpa")
confere("limpa: gate sai verde (exit 0)", rc2 == 0)
confere("limpa: zero achados", len(d2["achados"]) == 0)
if d2["achados"]:
    print("   achados indevidos na limpa:", [(a["codigo"], a["arquivo"]) for a in d2["achados"]])

# sem npm no PATH: a checagem de dependencias vira VERIFICAR, nunca aprova calada
rc3, d3 = roda("fixture-limpa", path="/usr/bin:/bin")
sem_npm = [a for a in d3["achados"] if a["codigo"] == "DEPENDENCIA_NAO_AUDITADA"]
confere("sem npm: avisa que as dependencias NAO foram auditadas", len(sem_npm) == 1 and sem_npm[0]["severidade"] == "VERIFICAR")

total = TOTAL_CONFERENCIAS[0]
print(f"\n{total - len(falhas)}/{total}")
sys.exit(1 if falhas else 0)
