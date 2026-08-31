# Cada achado explicado pra quem nunca foi dev

Linguagem de gente. Cada código que a varredura reporta, o que significa e a analogia.

## SEGREDO_NO_CODIGO (crítico)
Sua chave de API escrita direto no código é como a senha do banco anotada num post-it colado no
caixa eletrônico. Quem vê o código (ou o repositório) usa a sua conta e você paga a fatura.
**Correção:** a chave vai pro arquivo `.env` (que fica só na sua máquina) e o código lê com
`process.env.NOME` ou `os.environ`. E TROCA a chave no site do provedor, porque a que vazou
continua funcionando até você revogar.

## ENV_COMMITADO / ENV_NO_HISTORICO (crítico)
O `.env` é o cofre das senhas. Commitá-lo no git é tirar foto do cofre aberto e guardar no álbum:
mesmo que você apague depois, o álbum (histórico do git) guarda a foto. Quem clonar o repositório
vê tudo. **Correção:** tirar do rastreio, ignorar no `.gitignore`, trocar TODAS as chaves que
passaram por ele, e se o repositório for público, reescrever o histórico.

## GITIGNORE_SEM_ENV (alto)
Ainda não vazou, mas a porta está destrancada: o próximo `git add .` leva o `.env` junto.

## SERVICE_ROLE_NO_FRONTEND (crítico)
O Supabase tem duas chaves: a `anon` (pode ficar no site, as regras de RLS seguram) e a
`service_role` (ignora TODAS as regras). Colocar a service_role no frontend é dar a chave mestra
do prédio pra todo visitante. **Correção:** service_role só em backend ou edge function.

## SUPABASE_CONFERIR_RLS (verificar)
RLS é a regra de "cada um só vê o que é seu" dentro do banco. Tabela sem RLS no Supabase é
fichário aberto na recepção. Rode `references/rls-consulta.sql` no SQL Editor e ative RLS no
que aparecer marcado.

## DADO_PESSOAL_EM_LOG (alto)
Log é caderno de anotações do sistema. Imprimir CPF, e-mail ou telefone nele espalha dado pessoal
por lugares que ninguém audita (console, arquivos, serviços de log). Pela LGPD, log também é
tratamento de dado. **Correção:** tira o dado do log ou mascara.

## CPF_NO_CODIGO (alto)
CPF real em código ou teste é dado pessoal de alguém versionado pra sempre. Teste usa dado
inventado.

## CORS_ABERTO (médio)
CORS com `*` diz "qualquer site do mundo pode chamar a minha API". Restrinja ao seu domínio.

## ADMIN_SEM_SINAL_DE_AUTH (verificar)
A varredura achou uma tela de admin sem nenhum sinal de login no código. Pode ser falso alarme
(a proteção pode estar em outro lugar), por isso é "verificar": a pergunta a responder é "se eu
abrir essa URL numa aba anônima, entro?". Esconder o link NÃO é proteção.

## O que a varredura NÃO cobre
Ela olha o código parado. Não testa o site no ar (use `checar_deploy.py` pra isso), não invade
nada, não substitui os itens de arquitetura do checklist completo (threat model, backup,
migrations). Zero achado significa "esta varredura não achou nada", não "o projeto é seguro".
