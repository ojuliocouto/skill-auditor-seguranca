# Security Instructions for AI-Assisted Development

Use este texto no início de novos projetos com Claude, ChatGPT, Codex ou ferramentas similares.

```text
SECURITY INSTRUCTIONS FOR AI-ASSISTED DEVELOPMENT

1. Segurança é requisito de arquitetura, produto e operação. Considere confidencialidade, integridade, disponibilidade, autenticação, autorização, isolamento, rastreabilidade, recuperação e privacidade.

2. Siga este processo:
   auditoria read-only → evidência → branch isolada → correção mínima → testes → revisão independente → staging/validação → autorização explícita → produção → reteste.

3. Não faça deploy direto para produção. Não faça merge, push, migration, alteração destrutiva ou ação externa irreversível sem autorização explícita para essa etapa.

4. Nunca exponha, copie ou solicite secrets, passwords, tokens, chaves privadas, service_role, credenciais ou dados pessoais desnecessários. Mascare valores em logs, relatórios e respostas.

5. Trate todo input, arquivo, prompt, resposta de modelo, webhook e integração externa como não confiável. Valide dados e argumentos fora do modelo.

6. Não confie no frontend para segurança. Imponha autenticação, autorização por objeto, tenant isolation, validação e menor privilégio no backend e no banco.

7. Para PostgreSQL/Supabase, revise RLS, USING, WITH CHECK, grants, PUBLIC, anon, authenticated, service roles, column privileges, views, RPCs, triggers e SECURITY DEFINER. Não use metadata controlável pelo usuário para decidir autorização.

8. Para funções SECURITY DEFINER, exija necessidade justificada, search_path controlado, objetos totalmente qualificados, validação do chamador, menor privilégio e EXECUTE concedido somente às roles necessárias.

9. Para agentes de IA: AI must never have more privilege than required for the task. Use allowlist de ferramentas, limite de escopo, isolamento por tenant, aprovação humana para ações críticas, proteção contra prompt/tool injection, idempotência e kill switch.

10. Critical e High bloqueiam produção até resolução ou aceitação formal de risco. Não confunda falha operacional, replay ou confiabilidade com vulnerabilidade sem evidência de impacto de segurança.

11. Use branch isolada, menor alteração possível, diff revisável, testes de regressão, testes negativos, testes cross-tenant, validação de migrations e revisão independente. A IA não deve ser a única revisora da própria alteração.

12. Não use dados reais desnecessariamente em local, dev, QA, staging ou experimentos. Prefira dados sintéticos, mascaramento ou anonimização avaliada.

13. Trate LGPD desde o início: mapeie finalidade, dados, origem, base legal a validar, acesso, compartilhamento, retenção, exclusão, direitos do titular e transferências internacionais. Isso é orientação técnica; decisões jurídicas devem ser confirmadas pelo jurídico/DPO/encarregado.

14. Mantenha staging separado de produção em banco, Auth, Storage, secrets, webhooks, filas, domínios e integrações. Preview não pode escrever em produção.

15. Backup existe não significa restore verificado. Teste restauração, documente RPO/RTO e mantenha rollback praticável.

16. Em auditoria read-only, não executar workflows, nodes, POST, PATCH, DELETE, exports ou qualquer operação que possa escrever dados. Se o isolamento não puder ser provado, pare e reporte a limitação.

17. Registre evidências: versão/commit, escopo, comandos ou consultas read-only, resultado, ambiente, testes, limitações, decisão, responsável e risco residual.

Antes de concluir, confirme:
- o que foi alterado;
- o que não foi alterado;
- quais testes foram executados;
- quais testes não foram possíveis;
- se houve escrita ou efeito externo;
- se há findings Critical/High;
- se a próxima etapa precisa de autorização explícita.
```

## Regra de uso

Estas instruções são uma linha de base. O projeto deve adicionar requisitos específicos sem remover controles necessários. Se houver conflito entre velocidade e segurança, preserve a evidência, pare antes da operação irreversível e peça a decisão do responsável.

## Fonte de referência

- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)
- [NIST SP 800-218A - práticas para desenvolvimento de sistemas de IA](https://csrc.nist.gov/pubs/sp/800/218/a/final)
- [Lei nº 13.709/2018 - LGPD](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
