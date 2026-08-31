-- Cole no SQL Editor do Supabase (somente leitura).
-- Lista as tabelas do schema public SEM Row Level Security: qualquer uma que aparecer
-- esta legivel/gravavel por quem tiver a chave anon do seu projeto.
select schemaname, tablename,
       case when rowsecurity then 'RLS ATIVO' else 'SEM RLS <<< CORRIGIR' end as situacao
from pg_tables
where schemaname = 'public'
order by rowsecurity, tablename;

-- Tabela com RLS ativo mas SEM NENHUMA POLICY tambem bloqueia tudo (ou libera nada):
-- confira se cada tabela com RLS tem as policies que o app precisa.
select schemaname, tablename, policyname, cmd, roles
from pg_policies
where schemaname = 'public'
order by tablename, policyname;
