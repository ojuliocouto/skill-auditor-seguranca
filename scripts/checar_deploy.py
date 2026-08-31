#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Checa um site JA PUBLICADO: arquivos sensiveis acessiveis e headers de seguranca.

So faz GET (read-only). Uso: python3 checar_deploy.py https://seusite.com
Sai com 2 se algo CRITICO estiver exposto, 1 se faltarem headers, 0 se ok.
"""
import argparse
import sys
import urllib.error
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/140.0 Safari/537.36"}
# caminho -> assinatura no corpo que confirma exposicao real (evita falso positivo de SPA
# que devolve 200 com o index.html para qualquer rota)
CAMINHOS = [
    ("/.env",          ["=", "KEY", "SECRET", "TOKEN", "senha", "PASSWORD"]),
    ("/.env.local",    ["=", "KEY", "SECRET", "TOKEN"]),
    ("/.git/config",   ["[core]", "repositoryformatversion"]),
    ("/.git/HEAD",     ["ref:"]),
    ("/config.json",   ["key", "secret", "token", "password", "senha"]),
]
HEADERS_ESPERADOS = ["strict-transport-security", "x-content-type-options", "x-frame-options"]

def pega(url):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read(4096).decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return None, "", {}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("url", help="https://seusite.com")
    args = ap.parse_args()
    base = args.url.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    criticos = altos = 0
    print(f"=== CHECANDO DEPLOY: {base} ===\n")
    st, corpo, headers = pega(base + "/")
    if st is None:
        sys.exit("ERRO: site nao respondeu. Confira a URL.")

    for caminho, assinaturas in CAMINHOS:
        s, c, _ = pega(base + caminho)
        if s == 200 and any(a.lower() in c.lower() for a in assinaturas) and "<html" not in c[:200].lower():
            criticos += 1
            print(f"[CRITICO] {caminho} esta ACESSIVEL publicamente")
            print(f"    qualquer pessoa abre {base}{caminho} e le. Trocar as chaves expostas AGORA e bloquear o caminho no servidor.\n")
        else:
            print(f"[ok] {caminho} nao acessivel")

    faltando = [h for h in HEADERS_ESPERADOS if h not in {k.lower() for k in headers}]
    if faltando:
        altos += 1
        print(f"\n[ALTO] headers de seguranca ausentes: {', '.join(faltando)}")
        print("    em Cloudflare Pages: arquivo _headers na raiz do build; em Vercel: vercel.json > headers")
    else:
        print("\n[ok] headers de seguranca presentes")

    print(f"\nGATE: {'REPROVADO' if criticos else ('ATENCAO' if altos else 'aprovado nesta checagem')}")
    sys.exit(2 if criticos else (1 if altos else 0))

if __name__ == "__main__":
    main()
