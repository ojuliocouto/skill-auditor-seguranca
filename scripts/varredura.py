#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Varredura de seguranca do projeto: segredos, .env, dados pessoais em log, service_role,
webhook sem assinatura, segredo em variavel publica, senha sem hash, SQL concatenado,
HTML inseguro, API sem rate limit e dependencias vulneraveis (npm audit).

Gate executavel: sai com codigo 2 se houver CRITICO, 1 se houver ALTO, 0 se limpo.
Read-only: nao altera nenhum arquivo do projeto.

Uso: python3 varredura.py /caminho/do/projeto [--json]
"""
import argparse
import json
import os
import re
import shutil
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

# Regras de codigo so olham arquivo de codigo (README que cita "nunca use innerHTML" nao e achado)
EXT_CODIGO = {"js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte", "astro", "html",
              "py", "php", "rb", "go"}

# Variavel com prefixo que o bundler copia pro navegador: o nome diz que e segredo
PADRAO_VAR_PUBLICA = re.compile(r"\b((?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY|PUBLIC)_[A-Z0-9_]+)")
NOME_DE_SEGREDO = re.compile(r"SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|SENHA|TOKEN|OPENAI|ANTHROPIC|GROQ|CLAUDE|GEMINI|WEBHOOK")
NOME_PUBLICO_OK = re.compile(r"ANON|PUBLISHABLE|SITE_KEY|PUBLIC_KEY")

# Rota de webhook e sinais de que a assinatura e conferida
PADRAO_ROTA_WEBHOOK = re.compile(
    r"""(?i)(?:\.(?:post|all|use|route|on)\s*\(\s*["'`][^"'`]*webhook"""
    r"""|@\w+\.(?:post|route|api_route)\(\s*["'][^"']*webhook"""
    r"""|pathname\s*={2,3}\s*["'`][^"'`]*webhook)""")
SINAL_ASSINATURA = re.compile(
    r"(?i)constructEvent|signature|assinatura|hmac|verify|hottok|webhook_?secret|segredo|timingSafeEqual|validateWebhook|svix")

# Senha vinda do request gravada direto, e sinais de hash no arquivo
PADRAO_SENHA_CRUA = re.compile(
    r"""(?i)\b(?:password|senha|passwd)["']?\s*[:=]\s*(?:req\.body|request\.(?:form|json|body|data)|body|input|payload|form|args)\s*(?:\.|\[)""")
SINAL_HASH = re.compile(r"(?i)bcrypt|argon2|scrypt|pbkdf2|hashpw|make_password|password_hash|createHash|crypto\.subtle")

# SQL montado com dado: template sem tag, concatenacao, f-string, % e .format
SQL_KW = r"(?:\bselect\b[^`'\"]*\bfrom\b|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b)"
PADRAO_SQL_TEMPLATE = re.compile(r"(\w*)`([^`]*)`")
PADRAO_FSTRING = re.compile(r"""\b[fF](["'])(.*?)(?<!\\)\1""")
PADRAO_SQL_OUTROS = re.compile(
    rf"""(?i)(?:["']{SQL_KW}[^"']*["']\s*\+"""
    rf"""|["']{SQL_KW}[^"']*%s[^"']*["']\s*%"""
    rf"""|["']{SQL_KW}[^"']*\{{\}}[^"']*["']\.format\()""")
# Placeholder no SQL = os valores vao separados; o que se interpola costuma ser nome de tabela/lista de ?
PLACEHOLDER_SQL = re.compile(r"\?|\$\d+|(?<![:\w]):[A-Za-z_]\w*|%s|%\(\w+\)s")
DADO_DO_REQUEST = re.compile(r"(?i)\breq\b|request|body|params|query|input|form|payload|args")
# Codigo de teste roda com valor controlado pelo proprio teste: fica fora de SQL e HTML
PADRAO_ARQUIVO_TESTE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)/|\.(?:test|spec)\.\w+$|(?:^|/)test_\w+\.py$")
LINHA_MINIFICADA = 400  # linha maior que isso e bundle gerado, nao codigo escrito

EXPR_SEGURA = re.compile(r"""^\s*(?:[A-Z][A-Z0-9_]*|(?:Number|parseInt|parseFloat|int|float)\(.*\))\s*$""")

def sql_interpolado_inseguro(corpo, exprs, tem_params=False):
    """Interpolacao em SQL so e achado se nao ha placeholder (valor vai junto do comando)
    ou se o que entra vem do request. Constante em MAIUSCULA (nome de tabela) e numero
    convertido (Number(id)) nao carregam comando."""
    sem_exprs = re.sub(r"\$?\{[^}]*\}", "", corpo)  # SQL dentro da expressao nao conta
    if not exprs or not re.search(SQL_KW, sem_exprs, re.I):
        return False
    if any(DADO_DO_REQUEST.search(e) for e in exprs):
        return True
    arriscadas = [e for e in exprs if not EXPR_SEGURA.match(e)]
    if not arriscadas:
        return False
    # placeholder no texto ou gerado na expressao (ids.map(() => "?"), ", ".join("?" ...))
    return not (tem_params or PLACEHOLDER_SQL.search(sem_exprs) or any("?" in e or "$" in e for e in exprs))

# Depois da string vem argumento (, params) ou .bind(...): os valores vao separados
PARAMS_DEPOIS = re.compile(r"^\s*(?:,|\)\s*\.bind\s*\()")

def sql_inseguro(ln):
    for m in PADRAO_SQL_TEMPLATE.finditer(ln):
        exprs = re.findall(r"\$\{([^}]*)\}", m.group(2))
        if not m.group(1) and sql_interpolado_inseguro(m.group(2), exprs, PARAMS_DEPOIS.match(ln[m.end():])):
            return True
    for m in PADRAO_FSTRING.finditer(ln):
        exprs = re.findall(r"\{([^}]*)\}", m.group(2))
        if sql_interpolado_inseguro(m.group(2), exprs, PARAMS_DEPOIS.match(ln[m.end():])):
            return True
    return bool(PADRAO_SQL_OUTROS.search(ln))

# HTML montado com dado (XSS)
PADRAO_HTML_DIRETO = re.compile(r"dangerouslySetInnerHTML|\bv-html\s*=|\{@html\s|insertAdjacentHTML\s*\(|document\.write\s*\(")
PADRAO_INNERHTML = re.compile(r"\.(?:inner|outer)HTML\s*\+?=\s*(.+)$")
LITERAL_PURO = re.compile(r"""^(?:(["'])[^"'`]*\1|`[^`$]*`)\s*;?\s*$""")
SINAL_SANITIZA = re.compile(r"(?i)DOMPurify|sanitize|escapeHtml|escapar")

# Servidor com rota propria, e sinais de rate limit no projeto
PADRAO_ROTA_SERVIDOR = re.compile(
    r"""(?i)\b(?:app|router|server|fastify)\.(?:get|post|put|patch|delete|all)\s*\(|@app\.(?:route|get|post)\b"""
    r"""|\bnew\s+Hono\b|export\s+default\s*\{\s*(?:async\s+)?fetch|Deno\.serve\s*\(""")
SINAL_RATE_LIMIT = re.compile(r"(?i)rate.?limit|limiter|throttl|slowapi")

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

def auditar_dependencias(raiz, add):
    """Roda npm audit quando ha package.json na raiz. Sem lockfile, sem npm ou sem rede vira
    VERIFICAR: dependencia nao auditada nunca passa como aprovada."""
    if not os.path.exists(os.path.join(raiz, "package.json")):
        return
    def nao_auditada(motivo):
        add("DEPENDENCIA_NAO_AUDITADA", "VERIFICAR", "package.json", 0,
            f"as dependencias NAO foram auditadas: {motivo}",
            "rodar npm audit na maquina com npm e internet, ou gerar o package-lock.json (npm install)")
    if not os.path.exists(os.path.join(raiz, "package-lock.json")):
        return nao_auditada("o projeto nao tem package-lock.json (npm audit precisa dele)")
    npm = shutil.which("npm")
    if not npm:
        return nao_auditada("npm nao esta instalado neste computador")
    try:
        r = subprocess.run([npm, "audit", "--json"], cwd=raiz, capture_output=True, text=True, timeout=120)
        vul = json.loads(r.stdout)["metadata"]["vulnerabilities"]
    except Exception as e:
        return nao_auditada(f"npm audit falhou ({type(e).__name__}); sem internet o npm nao consulta a base")
    crit, alta, mod = vul.get("critical", 0), vul.get("high", 0), vul.get("moderate", 0)
    if crit or alta:
        add("DEPENDENCIA_VULNERAVEL", "ALTO", "package-lock.json", 0,
            f"npm audit: {crit} critica(s), {alta} alta(s), {mod} moderada(s) em pacotes do projeto",
            "rodar npm audit fix (e npm audit para ver o que sobra); atualizar o pacote ou trocar por outro mantido")
    elif mod:
        add("DEPENDENCIA_VULNERAVEL", "MEDIO", "package-lock.json", 0,
            f"npm audit: {mod} vulnerabilidade(s) moderada(s)",
            "rodar npm audit fix quando der")

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
        eh_teste = bool(PADRAO_ARQUIVO_TESTE.search(rel.replace(os.sep, "/")))
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
            ext = rel.split(".")[-1].lower()
            if eh_env or ext in EXT_CODIGO:
                for nome_var in PADRAO_VAR_PUBLICA.findall(ln):
                    if NOME_DE_SEGREDO.search(nome_var) and not NOME_PUBLICO_OK.search(nome_var):
                        add("SEGREDO_EM_VAR_PUBLICA", "CRITICO", rel, i,
                            f"{nome_var}: variavel com esse prefixo vai pro codigo do navegador, qualquer visitante le o valor",
                            "tirar o prefixo publico, usar a chave so no backend (API route, edge function) e TROCAR a chave")
                        break
            if ext not in EXT_CODIGO or len(ln) > LINHA_MINIFICADA:
                continue
            if not eh_teste and sql_inseguro(ln):
                add("SQL_CONCATENADO", "ALTO", rel, i,
                    "SQL montado com dado dentro da string (interpolacao, concatenacao ou formatacao): dado do usuario vira comando no banco (SQL injection)",
                    "usar query parametrizada ($1, ?, :nome) ou o query builder/ORM; nome de tabela interpolado so de lista fixa")
            if not eh_teste and not SINAL_SANITIZA.search(ln):
                m = PADRAO_INNERHTML.search(ln)
                if PADRAO_HTML_DIRETO.search(ln) or (m and not LITERAL_PURO.match(m.group(1).strip())):
                    add("HTML_INSEGURO", "MEDIO", rel, i,
                        "HTML montado com dado e injetado na pagina: se o dado vier do usuario, abre XSS",
                        "usar textContent / renderizacao normal do framework, ou sanitizar com DOMPurify antes")

    # 2b) regras que olham o arquivo inteiro: webhook e senha
    arquivos_rota, tem_rate_limit = [], False
    for caminho in arquivos_do_projeto(raiz):
        rel = os.path.relpath(caminho, raiz)
        ext = rel.split(".")[-1].lower()
        if os.path.basename(rel) == "package.json":
            try:
                if SINAL_RATE_LIMIT.search(open(caminho, encoding="utf-8", errors="replace").read()):
                    tem_rate_limit = True
            except OSError:
                pass
        if ext not in EXT_CODIGO or eh_arquivo_de_exemplo(rel):
            continue
        try:
            corpo = open(caminho, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        linhas = corpo.splitlines()
        if SINAL_RATE_LIMIT.search(corpo):
            tem_rate_limit = True
        if PADRAO_ROTA_SERVIDOR.search(corpo):
            arquivos_rota.append(rel)
        # sinais contam so no codigo: "// TODO verificar assinatura" nao protege nada
        so_codigo = re.sub(r"(?m)^\s*(?://|#|/?\*).*$", "", corpo)
        if not SINAL_ASSINATURA.search(so_codigo):
            for i, ln in enumerate(linhas, 1):
                if PADRAO_ROTA_WEBHOOK.search(ln):
                    add("WEBHOOK_SEM_ASSINATURA", "ALTO", rel, i,
                        "rota de webhook que nao confere assinatura/segredo: qualquer um que achar a URL manda um POST falso e libera plano sem pagar",
                        "validar a assinatura com a SDK oficial (Stripe constructEvent, hottok da Hotmart, HMAC do gateway) ANTES de ler o corpo; sem assinatura valida, responder 400/401")
        if not SINAL_HASH.search(so_codigo):
            for i, ln in enumerate(linhas, 1):
                if PADRAO_SENHA_CRUA.search(ln):
                    add("SENHA_SEM_HASH", "ALTO", rel, i,
                        "senha vinda do request gravada sem hash: quem ler o banco (ou um backup vazado) ve a senha do usuario",
                        "gravar so o hash (bcrypt ou argon2) e comparar com bcrypt.compare no login")
    if arquivos_rota and not tem_rate_limit:
        add("SEM_RATE_LIMIT", "MEDIO", sorted(arquivos_rota)[0], 0,
            f"o projeto tem rotas de servidor ({len(arquivos_rota)} arquivo(s)) e nenhum sinal de rate limit: login e API ficam abertos a forca bruta e enxurrada de requisicoes",
            "limitar requisicoes por IP/usuario (express-rate-limit, @upstash/ratelimit, slowapi) ou regra de rate limit no WAF/Cloudflare; se ja existe no WAF, registre e ignore")

    # 2c) dependencias com vulnerabilidade conhecida (npm audit)
    auditar_dependencias(raiz, add)

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
