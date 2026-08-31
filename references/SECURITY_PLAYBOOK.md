# Security Playbook

## Segurança de Software, Proteção de Dados e LGPD em Projetos com IA

**Versão:** 1.0  
**Status:** modelo genérico reutilizável  
**Idioma:** português  
**Aplicação:** sites, sistemas web, SaaS, CRMs, APIs, aplicações React/Next.js, PostgreSQL/Supabase, sistemas multi-tenant, automações, workers, agentes de IA e soluções para organizações públicas ou privadas.

> Este material é um guia técnico e operacional de segurança e privacidade. Não constitui parecer jurídico e não substitui análise jurídica especializada, orientação do encarregado/DPO, avaliação contratual ou validação regulatória. Base legal, prazos de retenção, comunicação de incidentes, transferências internacionais e atendimento a titulares devem ser confirmados para cada contexto.

## Como usar este playbook

Este documento define uma linha de base. Cada projeto deve transformar as recomendações em decisões registradas, testes reproduzíveis e evidências verificáveis. A ausência de uma tecnologia específica não elimina o controle: substitua o mecanismo, preserve o objetivo de segurança e documente a decisão.

O processo padrão é:

`auditoria read-only → evidência → branch isolada → correção mínima → testes → revisão independente → staging/validação → autorização explícita → produção → reteste`

### Por que cada etapa existe

1. **Auditoria read-only:** reduz o risco de alterar dados ou mascarar a condição original enquanto o problema é compreendido.
2. **Evidência:** transforma opiniões em fatos reproduzíveis: código, configuração, logs, resultados e versões.
3. **Branch isolada:** separa a correção do estado estável e facilita revisão, rollback e comparação.
4. **Correção mínima:** diminui superfície de mudança, regressões e dificuldade de atribuir causa.
5. **Testes:** verificam tanto o controle novo quanto os fluxos legítimos que devem continuar funcionando.
6. **Revisão independente:** reduz o risco de a mesma pessoa ou ferramenta repetir a mesma suposição.
7. **Staging/validação:** permite observar comportamento integrado sem expor produção.
8. **Autorização explícita:** separa conclusão técnica de autorização operacional ou jurídica.
9. **Produção controlada:** limita janela, escopo, privilégios e impacto potencial.
10. **Reteste:** confirma que o controle existe depois do deploy e não foi perdido por configuração, cache, migração ou integração.

---

# Parte I - Metodologia de segurança

## 1. Objetivos de segurança

Todo projeto deve declarar quais propriedades precisa proteger:

| Objetivo | Pergunta prática | Controles típicos |
|---|---|---|
| Confidencialidade | Quem pode ver este dado? | autenticação, autorização, criptografia, RLS, mascaramento |
| Integridade | Quem pode criar, alterar ou excluir? | validação, políticas, constraints, logs, aprovação |
| Disponibilidade | O serviço continua utilizável? | limites, redundância, backups, filas, recuperação |
| Autenticidade | Como sabemos quem está agindo? | MFA, sessão, assinatura, rotação de credenciais |
| Rastreabilidade | O que ocorreu, quando e por quem? | audit trail, IDs de correlação, logs protegidos |
| Isolamento | Um usuário/tenant acessa outro? | autorização por objeto, RLS, separação de ambientes |
| Menor privilégio | Cada componente tem somente o necessário? | escopos mínimos, roles, allowlists, service accounts |
| Defesa em profundidade | Um único erro derruba todo o controle? | camadas independentes e testes de bypass |
| Recuperação | É possível restaurar e provar isso? | backups, restore tests, RPO/RTO, runbooks |
| Privacidade por padrão | A configuração inicial é a mais restritiva? | buckets privados, logs mínimos, exports restritos |

Um controle só deve ser considerado existente quando houver evidência de implementação e, para controles críticos, evidência de execução.

## 2. Threat Modeling

O threat modeling deve ocorrer antes do desenvolvimento relevante, antes de novas integrações e antes de exposição pública. Refaça-o quando mudar o modelo de dados, o fluxo de autorização, os privilégios de uma automação ou a capacidade de um agente de IA.

### 2.1 O que mapear

- **Ativos:** dados pessoais, credenciais, tokens, código, modelos, prompts, arquivos, dinheiro, reputação e disponibilidade.
- **Atores:** visitantes, usuários, administradores, operadores, fornecedores, service accounts, jobs, workers e agentes de IA.
- **Perfis:** capacidades permitidas e proibidas por perfil, tenant, departamento e contexto.
- **Trust boundaries:** navegador/servidor, API/banco, aplicação/provedor externo, usuário/agente, staging/produção.
- **Superfícies de ataque:** login, reset, upload, importação, exportação, APIs, webhooks, RPCs, jobs e ferramentas de IA.
- **Fluxos de dados:** origem, transformação, armazenamento, transmissão, logs, cache, backup e exclusão.
- **Dependências:** bibliotecas, provedores, filas, analytics, e-mail, mensageria, gateways e modelos.
- **Ações administrativas:** alteração de roles, impersonação, exportação, exclusão, configuração de integrações e acesso a dados.

### 2.2 Perguntas mínimas

1. O que aconteceria se este ativo fosse lido, alterado, apagado ou indisponibilizado?
2. Qual é o menor conjunto de usuários e serviços que precisa acessá-lo?
3. O frontend está apenas exibindo uma regra ou o backend realmente a impõe?
4. Um identificador previsível permite trocar o objeto acessado?
5. Alguma integração recebe mais dados ou privilégio do que precisa?
6. O que acontece quando uma requisição é repetida, atrasada, duplicada ou forjada?
7. Que evidência ficará disponível depois de um incidente?

### 2.3 Template de threat model

| Asset | Threat | Attack Path | Impact | Existing Controls | Risk | Mitigation |
|---|---|---|---|---|---|---|
| Exemplo fictício: cadastro de cliente | acesso indevido | usuário troca o identificador na API | exposição de dados pessoais | autenticação | alto | autorização por objeto + teste cross-tenant |
|  |  |  |  |  |  |  |

## 3. Classificação de findings

### 3.1 SECURITY_SEVERITY

| Nível | Critério orientativo |
|---|---|
| **CRITICAL** | exploração provável com comprometimento amplo: bypass de autenticação, acesso massivo a dados sensíveis, execução remota ou alteração administrativa sem barreira efetiva |
| **HIGH** | impacto relevante e caminho de exploração realista: IDOR/BOLA, elevação de privilégio, tenant isolation quebrado, segredo exposto ou escrita não autorizada |
| **MEDIUM** | impacto limitado, pré-condições adicionais ou escopo restrito, mas com efeito de segurança concreto |
| **LOW** | fraqueza de baixo impacto direto, defesa incompleta ou exposição com exploração pouco provável |
| **INFORMATIONAL** | observação, melhoria ou ausência de impacto de segurança demonstrável |

Classifique com base em impacto, probabilidade, pré-condições, alcance, detectabilidade e capacidade de recuperação. Registre a justificativa; não use apenas o nome do bug.

### 3.2 Separar segurança de operação

Sempre registre campos independentes:

- `SECURITY_SEVERITY`: confidencialidade, integridade, disponibilidade por ataque, autenticação, autorização ou privacidade.
- `OPERATIONAL_SEVERITY`: falha de execução, replay, migração, latência, duplicidade ou confiabilidade sem exploração de segurança demonstrada.

Uma migration que falha por ordem incorreta pode ser operacionalmente grave, mas não deve ser chamada automaticamente de vulnerabilidade. O inverso também vale: uma falha de autorização pode existir mesmo quando o sistema continua disponível.

## 4. Security Gate

O gate é uma decisão registrada, não apenas uma impressão do revisor.

### Política mínima

- Qualquer `CRITICAL` aberto: `SECURITY_GATE = FAIL`.
- Qualquer `HIGH` sem aceitação formal de risco: `SECURITY_GATE = FAIL`.
- `MEDIUM`: exige análise de risco, plano e prazo; pode bloquear conforme o contexto.
- `LOW` e `INFORMATIONAL`: devem ser registrados e priorizados.
- Produção somente após gate aprovado, testes previstos e autorização explícita.
- Aceitação de risco deve identificar responsável, justificativa, prazo de expiração e controles compensatórios.

### Exemplos

```text
CRITICAL_OPEN: 0
HIGH_OPEN: 0
MEDIUM_OPEN: 2
RESTORE_VERIFIED: true
STAGING_VALIDATED: true
INDEPENDENT_REVIEW_COMPLETE: true
RUNTIME_TESTS_COMPLETE: true
SECURITY_GATE: PASS
```

```text
CRITICAL_OPEN: 0
HIGH_OPEN: 1
MEDIUM_OPEN: 0
RESTORE_VERIFIED: true
STAGING_VALIDATED: true
INDEPENDENT_REVIEW_COMPLETE: false
RUNTIME_TESTS_COMPLETE: false
SECURITY_GATE: FAIL
```

## 5. Controle de acesso

### 5.1 Autenticação e autorização são controles diferentes

- **Autenticação:** confirma a identidade ou o contexto da sessão.
- **Autorização:** decide se essa identidade pode executar aquela ação sobre aquele objeto, naquele tenant e naquele contexto.

Nunca trate `authenticated` como sinônimo de autorizado. Um usuário autenticado ainda precisa de verificação de ownership, role, permission, tenant, estado do recurso e finalidade.

### 5.2 RBAC e ABAC

- **RBAC:** papéis como leitor, operador, gestor e administrador.
- **ABAC:** atributos como tenant, departamento, estado do objeto, horário, origem, classificação do dado e justificativa.
- Use RBAC para capacidades estáveis e ABAC para decisões contextuais.
- Evite guardar autorização em metadados controláveis pelo usuário.
- Mudanças de role devem ser administrativas, auditadas e resistentes a mass assignment.

### 5.3 Testes de autorização

Para cada endpoint e ação, teste:

- usuário sem sessão;
- usuário autenticado sem permissão;
- usuário do mesmo tenant;
- usuário de outro tenant;
- administrador do tenant;
- administrador global, se existir;
- service account;
- objeto inexistente;
- identificador de outro objeto;
- tentativa de alterar campos protegidos;
- repetição e concorrência.

Procure especificamente IDOR/BOLA, elevação horizontal, elevação vertical, mass assignment e autorização apenas no frontend.

## 6. Multi-tenancy

O isolamento de tenants é um requisito de integridade e confidencialidade. `organization_id` ou `tenant_id` deve ser imposto no servidor, no banco e nas integrações relevantes.

### 6.1 Regras de arquitetura

- Não aceite tenant somente de campo enviado pelo navegador.
- Derive o tenant da sessão, de uma relação autorizada ou de contexto confiável.
- Verifique relações indiretas: usuário → equipe → organização → recurso.
- Aplique filtros no backend e políticas no banco; uma camada não substitui a outra.
- Trate exportação, importação, busca, webhooks, jobs e arquivos como parte do isolamento.
- Documente exceções administrativas e registre cada uso.
- Separe operações de `service_role` e jobs internos de operações de usuário.

### 6.2 Matriz mínima de testes

| Ator | SELECT | INSERT | UPDATE | DELETE | RPC | Storage | Exportação |
|---|---|---|---|---|---|---|---|
| User A / Org A | somente Org A | somente Org A | somente objetos permitidos de Org A | somente objetos permitidos | somente funções autorizadas | somente paths permitidos | somente dados de Org A |
| User B / Org B | não vê Org A | não cria em Org A | não altera Org A | não remove Org A | não atravessa tenant | não lê arquivos de Org A | não exporta Org A |
| Admin A | escopo administrativo de Org A | conforme função | conforme função | conforme função | conforme função | escopo de Org A | escopo de Org A + auditoria |
| Service Account | somente escopo declarado | somente escopo declarado | somente escopo declarado | somente escopo declarado | allowlist | paths declarados | finalidade registrada |

Repita os testes com IDs válidos de outro tenant, IDs inexistentes, filtros vazios, ordenação, paginação, importações e payloads com tenant forjado.

## 7. PostgreSQL, Supabase e RLS

RLS controla linhas; grants controlam acesso a objetos e colunas; a API expõe somente o que a combinação de schema, grants, policies e configuração permitir.

### 7.1 Checklist técnico

- RLS habilitado em toda tabela de schema exposto.
- `FORCE ROW LEVEL SECURITY` avaliado quando o owner ou jobs não devem bypassar RLS.
- Policies separadas e explícitas para `SELECT`, `INSERT`, `UPDATE` e `DELETE`.
- `USING` controla linhas visíveis/atingidas.
- `WITH CHECK` controla o estado resultante em `INSERT` e `UPDATE`.
- `auth.uid()` ou equivalente usado com o contexto correto.
- Policies restringem tenant, ownership e papel; `TO authenticated` sozinho não autoriza o objeto.
- `UPDATE` possui tanto controle da linha lida quanto do novo estado.
- Grants revisados para `PUBLIC`, `anon`, `authenticated`, roles técnicas e service roles.
- Column-level privileges usados quando alguns campos são privilegiados.
- Views avaliadas: views podem alterar a fronteira de RLS; considere `security_invoker` quando suportado ou schema não exposto.
- Funções auxiliares analisadas quanto a `SECURITY DEFINER`, `search_path` e `EXECUTE`.
- Realtime, Storage e RPCs avaliados separadamente.

No Supabase, uma tabela acessível pela Data API precisa de grants compatíveis e RLS coerente. RLS não transforma uma tabela exposta em segura automaticamente. Consulte a [documentação de RLS do Supabase](https://supabase.com/docs/guides/database/postgres/row-level-security) e a [documentação de Row Security Policies do PostgreSQL](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

### 7.2 Não usar metadata controlável para autorização

Metadados editáveis pelo próprio usuário não devem decidir role, tenant, permissões ou acesso. Prefira uma tabela protegida, `app_metadata` administrado ou uma função segura que derive a autorização de fonte confiável. Tokens podem permanecer desatualizados até serem renovados; trate isso no desenho.

## 8. `SECURITY DEFINER`

`SECURITY DEFINER` executa com os privilégios do proprietário da função. É uma ferramenta de fronteira privilegiada, não um atalho para resolver erro de permissão.

### Padrão recomendado quando realmente necessário

```sql
CREATE OR REPLACE FUNCTION internal.safe_operation(input_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
BEGIN
  -- Validar o chamador e o tenant antes da operação.
  -- Referenciar objetos com schema completo.
  NULL;
END;
$function$;

REVOKE EXECUTE ON FUNCTION internal.safe_operation(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION internal.safe_operation(uuid) TO authenticated;
```

### Checklist

- Existe necessidade real de bypassar RLS ou usar privilégios do owner?
- A função está em schema não exposto quando possível?
- `SET search_path = ''` foi aplicado?
- Todas as tabelas, funções e tipos estão totalmente qualificados?
- O chamador é validado no corpo da função?
- Tenant, ownership e finalidade são verificados?
- `EXECUTE` foi revogado de `PUBLIC`?
- Grants explícitos foram concedidos somente às roles necessárias?
- Entradas são validadas e não permitem SQL dinâmico inseguro?
- Função é idempotente e auditável?
- RPC, trigger e job que a chamam têm escopos distintos?

Funções novas podem receber `EXECUTE` para `PUBLIC` por padrão; revise a ACL explicitamente. Consulte a [documentação de privilégios de funções do PostgreSQL](https://www.postgresql.org/docs/current/perm-functions.html).

## 9. Migrations seguras e reproduzíveis

Uma migration é código de produção. Deve funcionar em banco vazio, banco acumulado e ambiente já parcialmente atualizado.

### 9.1 Verificações

- Executar replay desde zero.
- Executar sobre schema acumulado representativo.
- Confirmar ordering e dependências.
- Evitar dependência implícita em dados manuais.
- Avaliar transação, lock, tempo e impacto.
- Revisar `ALTER TABLE`, constraints, índices, views, triggers, functions, extensions e data migrations.
- Definir comportamento em retry e reexecução.
- Validar permissões e ACL depois de criar ou substituir objetos.
- Não corrigir manualmente o banco e declarar a migration resolvida.

### 9.2 `CREATE OR REPLACE FUNCTION`

`CREATE OR REPLACE FUNCTION` pode atualizar o corpo, mas não substitui livremente uma assinatura incompatível. Mudanças em tipo de retorno, parâmetros `OUT` ou `RETURNS TABLE` podem exigir remoção e recriação.

Quando for necessário usar `DROP FUNCTION + CREATE FUNCTION`:

1. confirme dependências;
2. preserve ou restaure grants;
3. restaure comments e configurações relevantes;
4. considere janela e lock;
5. teste views, triggers, RPCs e jobs dependentes;
6. execute replay desde zero e sobre schema acumulado.

## 10. Replay audit

Processo recomendado:

1. criar banco descartável do zero;
2. aplicar migrations em ordem;
3. capturar a primeira falha, não somente a última;
4. não corrigir objetos manualmente;
5. corrigir a migration no código;
6. revisar a correção;
7. recriar o ambiente;
8. repetir até obter replay limpo;
9. comparar schema, grants, policies, triggers e funções com o esperado.

Faça análise estática antes do replay para detectar ciclos entre functions, views, triggers, extensões e grants, reduzindo iterações desnecessárias.

## 11. Staging

Staging deve ser separado de produção em dados, autenticação, segredos e efeitos externos.

- banco/project ref separado;
- domínio separado;
- secrets e OAuth separados;
- Auth separado;
- Storage e buckets separados;
- webhooks apontando para endpoints de teste;
- filas e workers isolados;
- integrações externas em modo sandbox ou mock;
- dados sintéticos;
- logs e observabilidade segregados;
- nenhum segredo de produção reutilizado em Preview/staging;
- produção explicitamente protegida contra chamadas originadas de testes.

## 12. Dados sintéticos

Prefira dados fictícios em local, desenvolvimento, QA, demonstrações e staging.

Use:

- nomes fictícios;
- e-mails em domínios controlados;
- telefones não pertencentes a pessoas reais;
- documentos fictícios e inválidos para produção;
- UUIDs nunca usados em produção;
- organizações e tenants artificiais;
- arquivos sem conteúdo pessoal;
- tokens revogáveis e de curta duração.

Se o uso de dados reais for inevitável, registre necessidade, autorização, minimização, mascaramento, acesso, prazo de expiração e eliminação.

## 13. Secrets e credenciais

Proteja:

- `.env` e arquivos locais;
- chaves de API;
- tokens OAuth e webhooks;
- chaves de banco e Storage;
- `service_role` e equivalentes;
- credenciais de CI/CD;
- chaves de provedores de IA;
- certificados e chaves de assinatura.

Regras:

- nunca commitar secrets;
- usar secret manager quando possível;
- separar por ambiente;
- aplicar menor privilégio e expiração;
- rotacionar após exposição suspeita;
- mascarar logs e relatórios;
- nunca enviar secret completo ao chat, issue ou ferramenta de IA;
- não colocar segredo em `NEXT_PUBLIC_` ou bundle do navegador;
- revogar credenciais antigas depois da rotação.

## 14. APIs

Audite cada endpoint por:

- autenticação e sessão;
- autorização por objeto e tenant;
- validação de schema e tipos;
- limite de tamanho;
- rate limiting e abuso;
- paginação segura;
- filtragem de campos retornados;
- prevenção de mass assignment;
- proteção contra excessive data exposure;
- CORS restritivo;
- CSRF quando houver cookies e estado mutável;
- SSRF em URLs fornecidas pelo usuário;
- SQL injection, command injection e template injection;
- mensagens de erro sem dados internos;
- idempotência e replay;
- logs com correlação sem dados excessivos.

Use o [OWASP API Security Top 10](https://owasp.org/API-Security/) e o [OWASP Top 10](https://owasp.org/www-project-top-ten/) como referências de cobertura.

## 15. Storage

- buckets privados por padrão;
- policies testadas por usuário e tenant;
- signed URLs com expiração e escopo mínimo;
- validação de MIME real, extensão e tamanho;
- proteção contra path traversal;
- nomes de arquivo não confiáveis;
- varredura antimalware quando aplicável;
- impedir conteúdo ativo indevido;
- metadata sem dados pessoais desnecessários;
- exclusão alinhada a retenção, caches e backups;
- logs de download e exportação sensíveis;
- testes de acesso cruzado entre tenants.

## 16. Frontend

- tratar todo conteúdo externo como não confiável;
- escapar e sanitizar HTML;
- evitar `dangerouslySetInnerHTML` sem sanitização comprovada;
- usar CSP quando possível;
- nunca colocar segredo em código client-side;
- não armazenar tokens sensíveis em `localStorage` sem análise de risco;
- limitar dados em `sessionStorage`, URLs e estado global;
- não confiar em campos ocultos, disabled ou filtros visuais;
- revisar source maps e mensagens de erro;
- desabilitar logs pessoais em produção;
- validar autorização no backend mesmo que a UI esconda a ação.

## 17. Autenticação

Audite:

- MFA para perfis privilegiados;
- política de senha e proteção contra stuffing;
- magic links e expiração;
- reset de senha sem enumeração de contas;
- expiração e revogação de sessões;
- rotação e armazenamento de refresh tokens;
- signup e invite flows;
- metadata controlável pelo usuário;
- criação e alteração de roles;
- recuperação de conta;
- logout em dispositivos relevantes;
- alertas para mudança de credencial ou privilégio.

## 18. Webhooks e integrações

- verificar assinatura e timestamp;
- usar nonce/event ID e idempotência;
- impedir replay;
- validar origem sem depender somente de IP;
- limitar payload e tempo de processamento;
- separar credenciais por ambiente;
- mapear tenant de forma confiável;
- controlar retries e efeitos externos;
- registrar tentativa, resultado e correlação;
- não reenviar dados além do necessário.

## 19. Automação, n8n, workers e filas

- credenciais com escopo mínimo;
- workflows separados por ambiente;
- inputs tratados como não confiáveis;
- validação antes de chamar APIs;
- proteção contra execução duplicada;
- retries com backoff e limites;
- dead-letter ou fila de falhas;
- idempotência em escrita;
- logs sem tokens e dados pessoais desnecessários;
- aprovação humana antes de efeitos irreversíveis;
- acesso de worker limitado ao tenant/ação exigidos;
- desligamento seguro e recuperação documentada.

## 20. Agentes de IA

Princípio central:

`AI must never have more privilege than required for the task.`

### Controles

- separar modelo, orquestrador, ferramentas e dados;
- allowlist de ferramentas e argumentos;
- validar argumentos fora do modelo;
- nunca tratar texto do modelo como autorização;
- exigir confirmação humana para ações críticas;
- limitar leitura por tenant e finalidade;
- limitar escrita, exclusão, envio, compra e alteração de privilégio;
- proteger prompts, memória, embeddings e logs;
- combater prompt injection e tool injection;
- impedir exfiltração por resposta, arquivo, URL ou ferramenta;
- filtrar dados pessoais antes de enviar ao modelo quando possível;
- registrar modelo, versão, prompt policy, ferramentas e resultado;
- avaliar retenção e treinamento do provedor;
- testar comportamento adversarial e degradação segura;
- criar kill switch e limite de custo/volume.

Não conceda `service_role`, chave de banco ou acesso irrestrito a um agente somente para simplificar a integração.

Use, quando aplicável, o [NIST SP 800-218A para desenvolvimento seguro de sistemas de IA](https://csrc.nist.gov/pubs/sp/800/218/a/final).

## 21. Supply chain

- lockfiles versionados;
- versões fixadas ou política explícita de atualização;
- revisão de dependências novas;
- scan de vulnerabilidades e licença;
- atenção a typosquatting;
- remover pacotes sem manutenção;
- revisar scripts de instalação/build;
- proteger extensões e plugins;
- restringir GitHub Actions e tokens;
- verificar provenance quando disponível;
- separar dependência de build de dependência runtime;
- atualizar com teste e rollback.

## 22. CI/CD

- `main` protegida;
- revisão por pull request;
- checks obrigatórios;
- nenhum deploy direto sem gate;
- secrets isolados por ambiente;
- aprovação para produção;
- migration review;
- artefato imutável e identificável por commit;
- rollback praticável;
- logs de deploy preservados;
- permissão de CI mínima;
- branch preview sem acesso a produção.

O NIST descreve o SSDF como práticas organizadas para preparar a organização, proteger o software, produzir software seguro e responder a vulnerabilidades. Consulte o [NIST SSDF](https://csrc.nist.gov/projects/ssdf). O [CIS Controls v8.1](https://www.cisecurity.org/controls) pode complementar a priorização operacional.

## 23. Logging e auditoria

Registre de forma proporcional:

- login bem-sucedido e falho;
- mudança de role e permissões;
- acesso administrativo;
- leitura/exportação de dados sensíveis;
- criação, alteração e exclusão relevantes;
- falhas de autorização;
- uso de RPCs privilegiadas;
- execução de jobs e webhooks;
- decisões e ações de agentes de IA;
- IDs de correlação, timestamp e ambiente.

Não registre em claro:

- senhas;
- tokens;
- chaves de API;
- números completos de cartão;
- dados pessoais desnecessários;
- prompts com dados pessoais sem necessidade;
- payloads completos quando um resumo seguro basta.

Proteja logs contra alteração, limite acesso e defina retenção.

## 24. Backup e restore

`BACKUP EXISTS != RESTORE VERIFIED`

Verifique:

- cópia automática e manual quando necessário;
- checksum ou integridade;
- cópia fora do dispositivo/ambiente principal;
- restauração periódica em ambiente isolado;
- RPO e RTO documentados;
- schema, dados, Auth, Storage, configurações e chaves de recuperação;
- dependências externas e webhooks durante a restauração;
- acesso ao backup tão restrito quanto o acesso aos dados;
- expiração de cópias conforme retenção;
- runbook de recuperação e responsável.

## 25. Incident response

Fluxo mínimo:

`detect → contain → preserve evidence → revoke credentials → investigate → remediate → retest → communicate → postmortem`

O runbook deve definir:

- canal de acionamento;
- papéis e substitutos;
- severidade;
- isolamento sem destruir evidência;
- rotação/revogação;
- escopo de titulares e dados;
- comunicação interna e externa;
- avaliação jurídica/DPO;
- restauração e validação;
- lições aprendidas e prevenção.

Para incidentes envolvendo dados pessoais, consulte o procedimento atual da [ANPD para comunicação de incidentes](https://www.gov.br/anpd/pt-br/assuntos/incidente-de-seguranca). Não copie prazos legais de memória: confirme o regulamento vigente e a orientação jurídica do caso.

## 26. Revisão independente

Findings `CRITICAL` e `HIGH` devem passar por segunda revisão independente. A segunda pessoa ou ferramenta deve receber:

- escopo;
- versão/commit;
- evidência original;
- hipótese de impacto;
- testes executados;
- limitações;
- diff ou configuração relevante.

Claude, ChatGPT, Codex, SAST e scanners podem ampliar cobertura, mas não substituem julgamento, testes de autorização e validação runtime. Uma IA não deve simplesmente revisar a própria alteração sem uma verificação independente.

---

# Parte II - Proteção de Dados Pessoais e LGPD

## Aviso de escopo

Esta parte traduz princípios jurídicos em controles técnicos e operacionais. Não determina a base legal de um projeto, não substitui DPO/encarregado ou advogado e não garante conformidade por si só. A [LGPD no texto oficial consolidado](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm) deve ser lida junto das normas e orientações atuais da ANPD.

## 27. Conceitos básicos

| Conceito | Definição operacional |
|---|---|
| Dado pessoal | informação relacionada a pessoa natural identificada ou identificável |
| Dado pessoal sensível | dados como origem racial/étnica, religião, opinião política, filiação sindical, saúde, vida sexual, genético ou biométrico, quando vinculados a pessoa natural |
| Titular | pessoa natural a quem os dados se referem |
| Controlador | quem decide sobre o tratamento |
| Operador | quem trata dados em nome do controlador |
| Encarregado/DPO | canal de comunicação e função de orientação conforme o contexto aplicável |
| Tratamento | operações como coleta, acesso, uso, armazenamento, transmissão, compartilhamento e eliminação |
| Anonimização | uso de meios razoáveis para retirar a possibilidade de associação ao titular |
| Pseudonimização | substituição ou separação de identificadores, mantendo possibilidade de reidentificação sob controle |

As definições legais devem ser conferidas no texto vigente e no contexto concreto. A [ANPD mantém orientação sobre agentes de tratamento e encarregado](https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/guia-orientativo-para-definicoes-dos-agentes-de-tratamento-de-dados-pessoais-e-do-encarregado).

## 28. Data Mapping

Antes de desenvolver ou colocar em produção, mapeie:

`Dado → origem → finalidade → base legal → armazenamento → acesso → compartilhamento → retenção → exclusão`

| Dado | Origem | Finalidade | Base legal a validar | Armazenamento | Acessos | Compartilhamento | Retenção | Exclusão |
|---|---|---|---|---|---|---|---|---|
| Exemplo fictício: e-mail | formulário | criar conta | validar juridicamente | banco principal | usuário e suporte autorizado | provedor de e-mail | prazo documentado | rotina de exclusão |
|  |  |  |  |  |  |  |  |  |

Inclua cópias em logs, backups, caches, Storage, analytics, ferramentas de IA, exports e terceiros.

## 29. Data Classification

| Nível | Exemplos | Controles mínimos |
|---|---|---|
| Public | conteúdo publicado e não pessoal | integridade e revisão |
| Internal | informação operacional sem acesso público | autenticação e need-to-know |
| Confidential | contrato, configuração ou informação empresarial | acesso restrito, logs e criptografia conforme risco |
| Personal Data | nome, telefone, e-mail, identificador | finalidade, minimização, acesso e retenção |
| Sensitive Personal Data | saúde, biometria, religião, origem racial/étnica | controles reforçados, segregação e justificativa |
| Highly Restricted | documentos, credenciais, grandes exports, chaves | acesso excepcional, criptografia, auditoria e aprovação |

Exemplos de dados a classificar: nome, CPF, endereço, telefone, e-mail, geolocalização, documento, biometria, saúde, origem racial/étnica, religião, opinião política, filiação sindical e dados de crianças/adolescentes.

## 30. Minimização

`Não coletar um dado porque "pode ser útil no futuro".`

Para cada campo, pergunte:

- é realmente necessário?
- a finalidade está definida?
- pode ser opcional?
- pode ser pseudonimizado?
- pode ser agregado?
- pode ser apagado depois?
- precisa ser enviado a todos os serviços?
- precisa aparecer na resposta, URL ou log?

## 31. Finalidade e base legal

Registre para cada tratamento:

- finalidade específica;
- base legal proposta;
- responsável pela decisão;
- categorias de titulares e dados;
- prazo e critérios de retenção;
- compartilhamentos;
- comunicação ao titular;
- controles de segurança;
- revisão pelo jurídico/DPO.

O sistema pode operacionalizar uma decisão jurídica; não deve inventar ou escolher sozinho uma base legal.

## 32. Privacy by Design

Projete privacidade no schema e na arquitetura:

- separar dados sensíveis;
- limitar `SELECT` e respostas;
- não devolver CPF quando só o nome é necessário;
- mascarar identificadores;
- evitar dados pessoais em URLs;
- excluir dados de analytics quando desnecessários;
- separar tenant e departamento;
- iniciar com acesso privado;
- registrar finalidade e retenção como metadados operacionais;
- tornar exportação e compartilhamento ações explícitas.

## 33. Privacy by Default

Configurações padrão devem ser restritivas:

- bucket privado;
- perfil não público;
- exportação desabilitada ou limitada;
- logs minimizados;
- permissões mínimas;
- notificações sem dados sensíveis;
- links temporários;
- compartilhamento externo desativado;
- consentimentos não presumidos.

## 34. Dados pessoais em logs

Revise backend, browser, error tracking, analytics, APM, webhooks, workflows, banco e prompts de IA.

- remover campos desnecessários;
- mascarar identificadores;
- truncar payloads;
- bloquear tokens;
- limitar acesso;
- definir retenção;
- testar mensagens de erro;
- verificar logs de terceiros;
- impedir que o modo debug seja permanente.

## 35. Dados pessoais em URLs

Evite padrões como:

`/user?cpf=...`

URLs podem aparecer em histórico do navegador, proxies, analytics, CDN, logs e `Referer`. Prefira identificadores não sensíveis, corpo de requisição protegido, POST quando apropriado e políticas de referrer restritivas.

## 36. Exports

CSV, Excel, PDF e relatórios são superfícies críticas.

Audite:

- quem pode exportar;
- quais campos são incluídos;
- se o tenant é imposto;
- limites de volume e frequência;
- aprovação para exportações sensíveis;
- audit log;
- marcação de origem e finalidade;
- expiração de download;
- revogação de links;
- cópias temporárias e exclusão;
- proteção de arquivos baixados.

## 37. Ambientes não produtivos

Proíba o uso automático de dados reais em local, dev, staging, QA e demos.

Quando inevitável, exija autorização, minimização, mascaramento ou anonimização, acesso restrito, tempo curto, logs e eliminação comprovada. Nunca copie produção para um ambiente experimental por conveniência.

## 38. Retenção

Crie política por categoria:

| Categoria | Finalidade | Retenção ativa | Retenção em backup | Critério de exclusão | Responsável |
|---|---|---|---|---|---|
| Exemplo fictício |  |  |  |  |  |

Pergunte:

- por quanto tempo?
- por qual motivo?
- existe obrigação legal ou contratual?
- pode ser removido ou anonimizado antes?
- backups também expiram?
- caches, índices e exports foram incluídos?

## 39. Exclusão

Modele o ciclo completo:

- soft delete;
- hard delete;
- dados derivados;
- backups;
- caches;
- índices de busca;
- Storage;
- filas e dead-letter;
- terceiros;
- logs;
- embeddings e memória de IA.

Soft delete não equivale necessariamente a exclusão. Documente exceções, retenção legal e prazo operacional.

## 40. Direitos dos titulares

Crie capacidade para receber, verificar, atender e registrar solicitações de:

- informação;
- confirmação;
- acesso;
- correção;
- anonimização;
- bloqueio;
- eliminação quando aplicável;
- portabilidade quando aplicável;
- informação sobre compartilhamento;
- revogação de consentimento quando aplicável;
- oposição e revisão de decisões automatizadas quando aplicável.

O fluxo deve validar a identidade do solicitante, evitar exposição a terceiros, respeitar exceções legais e registrar prazo, decisão e evidência. Consulte a [orientação da ANPD sobre direitos dos titulares](https://www.gov.br/anpd/pt-br/assuntos/titular-de-dados-1/direito-dos-titulares).

## 41. Dados sensíveis

Use controles adicionais:

- acesso restrito;
- criptografia em trânsito e repouso;
- field-level encryption quando necessário;
- logging de acesso;
- mascaramento;
- segregação;
- justificativa de uso;
- retenção mínima;
- revisão de terceiros e IA;
- bloqueio de exportação por padrão.

## 42. Crianças e adolescentes

O tratamento desse público exige atenção reforçada, análise do melhor interesse, controles de idade/responsável quando aplicável e avaliação jurídica/DPO. Não implemente conclusões simplistas nem presuma que um checkbox resolve o risco.

## 43. Setor público

Para prefeituras, autarquias, secretarias e órgãos públicos, considere:

- grande volume de dados de cidadãos;
- integração entre secretarias e fornecedores;
- perfis internos e segregação por função/departamento;
- dados sensíveis e grupos vulneráveis;
- transparência versus privacidade;
- rastreabilidade de consulta e exportação;
- acesso de terceiros;
- logs administrativos imutáveis;
- retenção e eliminação compatíveis com deveres públicos;
- bases legais, competência e instrumentos formais;
- continuidade, disponibilidade e prestação de contas.

Use a [LGPD no texto oficial](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm) e materiais atuais da ANPD sobre tratamento pelo poder público. A solução técnica deve ser revisada pelo órgão responsável, jurídico e encarregado.

## 44. Compartilhamento com terceiros

Mapeie cloud, e-mail, mensageria, analytics, IA, automação, gateways, fornecedores e APIs.

Pergunta obrigatória:

`Que dados pessoais saem do sistema e para qual empresa, com qual finalidade, sob qual controle e por quanto tempo?`

Registre papel de controlador/operador quando aplicável, instruções, contrato, suboperadores, segurança, localização, retenção, retorno e exclusão.

Para transferências internacionais, valide mecanismo aplicável, transparência e garantias segundo a legislação e regulamentação atual da ANPD. Consulte o [Regulamento de Transferência Internacional de Dados](https://www.gov.br/anpd/pt-br/assuntos/assuntos-internacionais/transferencia-internacional-de-dados).

## 45. IA e LGPD

Verifique:

- quais dados pessoais são enviados a modelos;
- se prompts e arquivos ficam retidos;
- embeddings e vector databases;
- logs do provedor;
- uso para treinamento;
- subprocessadores;
- região e transferência internacional;
- redaction e minimização;
- memória persistente;
- direitos de acesso, correção e exclusão;
- uso de dados em avaliação e fine-tuning.

Princípio:

`Não enviar dados pessoais para um modelo de IA sem necessidade, base, controle e conhecimento do fluxo.`

Use dados sintéticos para testes e exija aprovação para ações autônomas que possam produzir efeito jurídico, financeiro, discriminatório ou relevante sobre pessoas.

## 46. Criptografia

- TLS para transporte;
- encryption at rest;
- field-level encryption para campos de alto risco;
- hashing para senhas e verificadores adequados;
- encryption para dados recuperáveis;
- chaves separadas por ambiente;
- rotação e revogação;
- acesso às chaves auditado;
- nunca confundir hashing com encryption;
- avaliar CPF/documentos conforme risco e necessidade.

## 47. Pseudonimização e anonimização

- **Pseudonimização:** reduz exposição direta, mas os dados continuam potencialmente pessoais se houver possibilidade de reidentificação.
- **Anonimização:** exige avaliar meios razoáveis e disponíveis para reidentificação no contexto concreto.

Separe a tabela/chave de reidentificação, limite acesso, controle correlação e teste risco de reidentificação por combinação de campos.

## 48. Data breach

Checklist técnico:

1. identificar e classificar o evento;
2. conter sem destruir evidências;
3. preservar logs, snapshots e timeline;
4. determinar dados e titulares afetados;
5. estimar quantidade, categorias e duração;
6. revogar acessos e rotacionar credenciais;
7. corrigir causa e validar o controle;
8. acionar jurídico/encarregado/DPO e responsáveis;
9. avaliar comunicação conforme LGPD e regulamentação vigente;
10. comunicar titulares quando aplicável;
11. documentar decisão, incertezas e medidas;
12. realizar postmortem.

Não apresente prazo jurídico absoluto sem verificar a norma vigente e a orientação competente. A ANPD mantém um procedimento atualizado para [Comunicação de Incidente de Segurança](https://www.gov.br/anpd/pt-br/assuntos/incidente-de-seguranca).

---

# Parte III - Templates reutilizáveis

## Finding template

```text
FINDING_ID:
TITLE:
CATEGORY:
SECURITY_SEVERITY:
OPERATIONAL_SEVERITY:
STATUS:
AFFECTED_OBJECT:
VERSION_OR_COMMIT:
EVIDENCE:
ATTACK_PATH:
IMPACT:
PRECONDITIONS:
REPRODUCTION:
MINIMAL_REMEDIATION:
TEST_PLAN:
INDEPENDENT_REVIEW:
RUNTIME_VALIDATION:
OWNER:
DUE_DATE:
RESIDUAL_RISK:
```

## Security Gate template

```text
CRITICAL_OPEN:
HIGH_OPEN:
MEDIUM_OPEN:
LOW_OPEN:
RESTORE_VERIFIED:
STAGING_VALIDATED:
INDEPENDENT_REVIEW_COMPLETE:
RUNTIME_TESTS_COMPLETE:
ROLLBACK_READY:
EXPLICIT_AUTHORIZATION:
SECURITY_GATE:
DECISION_OWNER:
DECISION_DATE:
NOTES:
```

## Data inventory template

```text
DATA_FIELD:
CLASSIFICATION:
DATA_SUBJECT:
PURPOSE:
LEGAL_BASIS_TO_VALIDATE:
SOURCE:
STORAGE:
ACCESS_ROLES:
TENANT_SCOPE:
THIRD_PARTIES:
INTERNATIONAL_TRANSFER:
RETENTION:
DELETION_METHOD:
ENCRYPTION:
PSEUDONYMIZATION:
LOGGED:
EXPORTED:
AI_PROCESSING:
OWNER:
```

## Threat model template

```text
ASSET:
ACTOR:
ENTRY_POINT:
TRUST_BOUNDARY:
THREAT:
IMPACT:
LIKELIHOOD:
EXISTING_CONTROL:
RECOMMENDED_CONTROL:
TEST:
EVIDENCE:
OWNER:
```

## Production change template

```text
CHANGE:
BRANCH:
COMMIT:
REVIEW:
SECURITY_FINDINGS:
STAGING_RESULT:
BACKUP:
RESTORE_VERIFIED:
ROLLBACK:
AUTHORIZATION:
DEPLOY_RESULT:
POST_DEPLOY_TEST:
EVIDENCE_LINKS:
```

---

# Parte IV - Regras para desenvolvimento assistido por IA

Use estas regras como complemento do processo do projeto:

- segurança é requisito de produto e arquitetura;
- nunca fazer deploy diretamente para produção;
- nunca expor secrets, tokens ou dados reais desnecessários;
- nenhuma alteração destrutiva sem autorização explícita;
- `CRITICAL` e `HIGH` bloqueiam produção até tratamento ou aceitação formal;
- usar branch isolada;
- fazer a menor correção segura;
- executar testes proporcionais ao risco;
- solicitar revisão independente;
- usar dados sintéticos sempre que possível;
- tratar LGPD desde o schema e o threat model;
- manter staging realmente separado;
- validar restore, não apenas a existência de backup;
- registrar evidência, versão, decisão e limitações;
- não executar workflows ou ações externas durante auditorias read-only;
- não considerar a resposta da IA como prova sem verificar no código, configuração ou runtime.

## Referências principais

- [Lei nº 13.709/2018 - LGPD, Planalto](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
- [ANPD - Guia de Segurança da Informação para agentes de pequeno porte](https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/processo-guia-orientativo-sobre-seguranca-da-informacao-para-agentes-de-tratamento-de-pequeno-porte.pdf)
- [ANPD - Agentes de tratamento e encarregado](https://www.gov.br/anpd/pt-br/centrais-de-conteudo/materiais-educativos-e-publicacoes/guia-orientativo-para-definicoes-dos-agentes-de-tratamento-de-dados-pessoais-e-do-encarregado)
- [ANPD - Direitos dos titulares](https://www.gov.br/anpd/pt-br/assuntos/titular-de-dados-1/direito-dos-titulares)
- [ANPD - Transferência internacional](https://www.gov.br/anpd/pt-br/assuntos/assuntos-internacionais/transferencia-internacional-de-dados)
- [ANPD - Comunicação de incidente de segurança](https://www.gov.br/anpd/pt-br/assuntos/incidente-de-seguranca)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)
- [NIST SP 800-218A - IA](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [CIS Critical Security Controls](https://www.cisecurity.org/controls)
- [PostgreSQL Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL Function Privileges](https://www.postgresql.org/docs/current/perm-functions.html)
- [Supabase Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)

> As fontes devem ser rechecadas quando o projeto for iniciado, especialmente para mudanças regulatórias, versões de dependências, provedores de IA, transferências internacionais e requisitos setoriais.
