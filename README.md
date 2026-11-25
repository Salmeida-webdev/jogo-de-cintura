# Jogo de Cintura

Portal editorial sobre trabalho, negócios, tecnologia e carreira, com painel administrativo de publicação.

## Aplicação

- Portal responsivo com matérias, categorias, busca, autores, leitura individual e metadados para compartilhamento e mecanismos de busca.
- Painel editorial protegido por senha, com gestão de matérias, revisão, publicação, agendamento manual, autores, categorias, tags e histórico.
- API em Cloudflare Workers com autenticação assinada, limite de tentativas de acesso e validação de conteúdo no servidor.
- Persistência em Cloudflare D1. As últimas 50 versões completas do conteúdo ficam registradas para recuperação e auditoria técnica.
- Publicação estática no Netlify. Uma Edge Function gera um nonce por resposta HTML e aplica CSP com `strict-dynamic`; `script-src` não libera `unsafe-inline`.
- Fotografias editoriais em WebP para reduzir o peso de carregamento.

## Estrutura

```text
assets/                  Identidade visual e fotografias editoriais
cloudflare/worker.js     API, autenticação e persistência
cloudflare/schema.sql   Estrutura do banco D1
cloudflare/wrangler.toml Binding do Worker ao banco
netlify/edge-functions/ CSP por requisição e cabeçalhos de segurança
app.js                   Portal e painel
styles.css               Layouts e regras responsivas
netlify.toml              Publicação e Edge Function
_redirects                Proxy de API para o Worker
```

## Desenvolvimento local

Com o Netlify CLI instalado, execute na pasta do projeto:

```bash
netlify dev --dir .
```

O uso de um servidor estático simples não executa o proxy `/api` nem a Edge Function de CSP. Para conferir apenas o portal sem API, `python3 -m http.server 4173` serve os arquivos em `http://localhost:4173`.

## Operação

- O segredo `ADMIN_PASSWORD` fica somente no ambiente do Worker; ele não está neste repositório nem no código do navegador.
- Para trocar a senha, atualize o segredo no Worker `jogo-de-cintura-api`. Para invalidar sessões existentes, atualize também `SESSION_SECRET`.
- Se o domínio Netlify mudar, atualize o binding `APP_ORIGIN` do Worker e publique uma nova versão.
- A API aceita gravações apenas com sessão administrativa válida. O endpoint público retorna somente matérias publicadas e os autores, categorias e tags usados por elas.
- Agendamentos registram data e horário, mas a publicação continua exigindo confirmação no painel.

## Banco de dados

O banco `jogo_de_cintura` tem três tabelas: `site_content` guarda o estado editorial atual, `content_revisions` mantém as últimas 50 versões e `login_attempts` controla tentativas de acesso. O arquivo `cloudflare/schema.sql` documenta essa estrutura.
