#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Varredura de seguranca do projeto: segredos, .env, dados pessoais em log, service_role.

Gate executavel: sai com codigo 2 se houver CRITICO, 1 se houver ALTO, 0 se limpo.
Read-only: nao altera nenhum arquivo do projeto.

Uso: python3 varredura.py /caminho/do/projeto [--json]
"""
import argparse
import json
import os
import re
import subprocess
import sys

IGNORAR_DIRS = {".git", "node_modules", "dist", "build", ".next", "vendor", "__pycache__",
                ".venv", "venv", ".cache", "coverage", ".turbo", "out"}
EXT_TEXTO = {".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".java", ".go", ".rs",
             ".html", ".css", ".scss", ".json", ".yml", ".yaml", ".toml", ".env", ".md",
             ".sql", ".sh", ".txt", ".vue", ".svelte", ".astro", ".mjs", ".cjs"}
MAX_BYTES = 1_000_000

# Padroes de segredo real (formato conhecido de provedores). Grupo 1 = o que reportar mascarado.
PADROES_SEGREDO = [
    ("chave OpenAI",        re.compile(r"\b(sk-[A-Za-z0-9_-]{20,})")),
    ("chave Groq",          re.compile(r"\b(gsk_[A-Za-z0-9]{20,})")),
    ("chave Google",        re.compile(r"\b(AIza[0-9A-Za-z_-]{30,})")),
    ("token GitHub",        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})")),
    ("chave AWS",           re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("token Notion",        re.compile(r"\b(ntn_[A-Za-z0-9]{20,})")),
    ("token Slack",         re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})")),
    ("chave Stripe",        re.compile(r"\b([sr]k_live_[A-Za-z0-9]{20,})")),
    ("chave privada",       re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    ("JWT em codigo",       re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("senha hardcoded",     re.compile(r"""(?i)(?:password|senha|passwd)\s*[:=]\s*["']([^"'\s]{6,})["']""")),
]
# Atribuicao generica de segredo (var com nome sensivel recebendo literal longa)
PADRAO_VAR_SENSIVEL = re.compile(
    r"""(?i)\b(?:api[_-]?key|secret|token|credencial|credential)[a-z0-9_]*\s*[:=]\s*["']([A-Za-z0-9_\-\./+=]{16,})["']""")
FALSOS_VALORES = re.compile(r"(?i)fake|exemplo|example|placeholder|xxx|test|sua[_-]?chave|your[_-]?key|<|>|\{|\$")

PADRAO_LOG = re.compile(r"(?i)\b(?:console\.(?:log|info|warn|error)|print|logger\.\w+|logging\.\w+)\s*\(")
# So acusa quando a palavra e CAMPO (chave de objeto, acesso de propriedade ou interpolacao),
# nao palavra solta em texto de ajuda ("uso: --senha X" nao e vazamento).
CAMPOS_PESSOAIS = r"(?:cpf|rg|email|e_mail|telefone|phone|celular|senha|password|cartao|card_number|endereco|address|data_nascimento|birth)"
PADRAO_DADO_PESSOAL = re.compile(
    rf"(?i)(?:\.\s*{CAMPOS_PESSOAIS}\b|\b{CAMPOS_PESSOAIS}\s*[:=]|\$\{{[^}}]*{CAMPOS_PESSOAIS}|\[[\'\"]{CAMPOS_PESSOAIS}[\'\"]\])")
PADRAO_CPF_LITERAL = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
PADRAO_CORS = re.compile(r"""(?i)(?:access-control-allow-origin["'\s:]+\*|origin\s*:\s*["']\*["'])""")

def mascara(v):
    return v[:6] + "..." + v[-3:] if len(v) > 12 else v[:3] + "..."

def eh_arquivo_de_exemplo(rel):
    n = os.path.basename(rel).lower()
    return any(t in n for t in (".example", ".sample", ".template")) or "/fixture" in rel.replace(os.sep, "/")

def arquivos_do_projeto(raiz):
    for dirpath, dirnames, filenames in os.walk(raiz):
        dirnames[:] = [d for d in dirnames if d not in IGNORAR_DIRS]
        for f in filenames:
            caminho = os.path.join(dirpath, f)
            ext = os.path.splitext(f)[1].lower()
            if ext not in EXT_TEXTO and not f.startswith(".env"):
                continue
            try:
                if os.path.getsize(caminho) > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield caminho

def git(raiz, *args):
    try:
        r = subprocess.run(["git", "-C", raiz, *args], capture_output=True, text=True, timeout=60)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None

def varrer(raiz):
    achados = []
    def add(codigo, sev, arquivo, linha, detalhe, correcao):
        achados.append({"codigo": codigo, "severidade": sev, "arquivo": arquivo,
                        "linha": linha, "detalhe": detalhe, "correcao": correcao})

    # 1) .env rastreado pelo git (working tree e historico)
    rastreados = git(raiz, "ls-files")
    if rastreados is None:
        # fallback declarado: sem git, as checagens de historico nao rodam, e isso e dito
        add("SEM_GIT", "VERIFICAR", ".", 0,
            "o projeto nao e um repositorio git (ou o git nao esta instalado): as checagens de "
            ".env commitado e de historico foram PULADAS, nao aprovadas",
            "se o projeto usa git em outro lugar, rode a varredura la; se nao usa, ignore este aviso")
    if rastreados is not None:
        for f in rastreados.splitlines():
            base = os.path.basename(f)
            if base.startswith(".env") and not eh_arquivo_de_exemplo(f):
                add("ENV_COMMITADO", "CRITICO", f, 0,
                    "arquivo .env esta versionado no git: todo segredo dele vai junto em qualquer clone ou push",
                    "git rm --cached no arquivo, adicionar ao .gitignore, TROCAR todas as chaves que estavam nele, e limpar o historico antes de repo publico")
        hist = git(raiz, "log", "--all", "--name-only", "--pretty=format:")
        if hist:
            no_hist = {f for f in hist.splitlines()
                       if os.path.basename(f).startswith(".env") and not eh_arquivo_de_exemplo(f)}
            ainda = set(rastreados.splitlines())
            for f in sorted(no_hist - ainda):
                add("ENV_NO_HISTORICO", "CRITICO", f, 0,
                    "um .env ja foi commitado no passado: remover do rastreio NAO apaga o historico, quem clonar ve",
                    "trocar as chaves que passaram por ele e reescrever o historico (git filter-repo) antes de publicar")
        gi = os.path.join(raiz, ".gitignore")
        conteudo_gi = open(gi, encoding="utf-8", errors="replace").read() if os.path.exists(gi) else ""
        if ".env" not in conteudo_gi:
            add("GITIGNORE_SEM_ENV", "ALTO", ".gitignore", 0,
                "o .gitignore nao ignora .env: o proximo git add . versiona os segredos",
                "adicionar as linhas .env e .env.* ao .gitignore")

    # 2) varredura arquivo a arquivo
    for caminho in arquivos_do_projeto(raiz):
        rel = os.path.relpath(caminho, raiz)
        if eh_arquivo_de_exemplo(rel):
            continue
        eh_env = os.path.basename(rel).startswith(".env")
        try:
            linhas = open(caminho, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        for i, ln in enumerate(linhas, 1):
            if not eh_env:  # segredo dentro do .env local e esperado; fora dele nao
                for nome, pad in PADROES_SEGREDO:
                    m = pad.search(ln)
                    if m and not FALSOS_VALORES.search(m.group(1)):
                        add("SEGREDO_NO_CODIGO", "CRITICO", rel, i,
                            f"{nome} escrita direto no codigo ({mascara(m.group(1))})",
                            "mover para variavel de ambiente (.env fora do git) e TROCAR a chave no provedor, porque ela ja vazou")
                        break
                else:
                    m = PADRAO_VAR_SENSIVEL.search(ln)
                    if m and not FALSOS_VALORES.search(m.group(1)):
                        add("SEGREDO_NO_CODIGO", "ALTO", rel, i,
                            f"variavel sensivel com valor fixo no codigo ({mascara(m.group(1))})",
                            "mover o valor para variavel de ambiente e conferir se precisa trocar")
            if "service_role" in ln.lower() and rel.split(".")[-1] in ("js","jsx","ts","tsx","html","vue","svelte"):
                add("SERVICE_ROLE_NO_FRONTEND", "CRITICO", rel, i,
                    "a chave service_role do Supabase ignora TODAS as regras de RLS; no frontend qualquer visitante vira admin do banco",
                    "usar so a chave anon no frontend; service_role fica em backend/edge function")
            if PADRAO_LOG.search(ln) and PADRAO_DADO_PESSOAL.search(ln):
                add("DADO_PESSOAL_EM_LOG", "ALTO", rel, i,
                    "log imprimindo campo que parece dado pessoal (LGPD: log tambem e tratamento de dado)",
                    "remover o dado do log ou mascarar (ex: só os 3 primeiros digitos)")
            if PADRAO_CPF_LITERAL.search(ln):
                add("CPF_NO_CODIGO", "ALTO", rel, i,
                    "CPF real escrito no codigo ou em arquivo versionado",
                    "remover; teste usa CPF sintetico obviamente falso (todos os digitos zero, sem pontuacao)")
            if PADRAO_CORS.search(ln):
                add("CORS_ABERTO", "MEDIO", rel, i,
                    "CORS liberado para qualquer origem (*)",
                    "restringir ao dominio real do frontend")

    # 3) heuristica de admin sem protecao
    for caminho in arquivos_do_projeto(raiz):
        rel = os.path.relpath(caminho, raiz)
        nome = os.path.basename(rel).lower()
        if "admin" in nome and rel.split(".")[-1] in ("html","js","jsx","ts","tsx","vue","svelte"):
            try:
                corpo = open(caminho, encoding="utf-8", errors="replace").read().lower()
            except OSError:
                continue
            if not re.search(r"auth|login|session|token|jwt|middleware|getserversession|useuser", corpo):
                add("ADMIN_SEM_SINAL_DE_AUTH", "VERIFICAR", rel, 0,
                    "arquivo de admin sem nenhum sinal de autenticacao no proprio codigo (heuristica: conferir a mao)",
                    "garantir que a rota exige login NO BACKEND; esconder o link nao protege")

    # 4) Supabase presente = lembrar do RLS
    usa_supabase = any("supabase" in open(c, encoding="utf-8", errors="replace").read().lower()
                       for c in arquivos_do_projeto(raiz)
                       if os.path.basename(c) in ("package.json", "requirements.txt"))
    if usa_supabase:
        add("SUPABASE_CONFERIR_RLS", "VERIFICAR", "package.json", 0,
            "o projeto usa Supabase: tabela sem RLS fica legivel por qualquer um com a chave anon",
            "rodar a consulta de references/rls-consulta.sql no SQL Editor do Supabase e ativar RLS no que aparecer")
    return achados

ORDEM = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "VERIFICAR": 3}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("projeto", help="raiz do projeto a varrer")
    ap.add_argument("--json", action="store_true", help="saida em JSON")
    args = ap.parse_args()
    raiz = os.path.abspath(args.projeto)
    if not os.path.isdir(raiz):
        sys.exit(f"ERRO: {raiz} nao e um diretorio")

    achados = sorted(varrer(raiz), key=lambda a: (ORDEM[a["severidade"]], a["arquivo"], a["linha"]))
    criticos = sum(1 for a in achados if a["severidade"] == "CRITICO")
    altos = sum(1 for a in achados if a["severidade"] == "ALTO")

    if args.json:
        print(json.dumps({"achados": achados, "criticos": criticos, "altos": altos},
                         ensure_ascii=False, indent=1))
    else:
        print(f"=== AUDITORIA DE SEGURANCA: {raiz} ===\n")
        if not achados:
            print("Nenhum achado. Isso NAO prova que o projeto e seguro: prova que esta varredura nao achou nada.")
        for a in achados:
            onde = f"{a['arquivo']}:{a['linha']}" if a["linha"] else a["arquivo"]
            print(f"[{a['severidade']}] {a['codigo']}  {onde}")
            print(f"    problema: {a['detalhe']}")
            print(f"    corrigir: {a['correcao']}\n")
        print(f"TOTAL: {len(achados)} achado(s) | CRITICO: {criticos} | ALTO: {altos}")
        if criticos:
            print("GATE: REPROVADO. Nao publique nem entregue com achado CRITICO aberto.")
        elif altos:
            print("GATE: ATENCAO. Corrija os ALTOs antes de entregar a cliente.")
        else:
            print("GATE: aprovado nesta varredura.")
    sys.exit(2 if criticos else (1 if altos else 0))

if __name__ == "__main__":
    main()
