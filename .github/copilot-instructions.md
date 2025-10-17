## Contexto rápido

Este repositório contém utilitários e um proxy para a API Zendesk usado pelo frontend (conecta). As partes principais são:

- `app.py` — pequeno servidor Flask que atua como proxy para chamadas Zendesk e oferece um endpoint de login que gera um JWT para testes.
- `conecta.js` — código frontend que consome o proxy. Salva o JWT em `localStorage` como `jwt_token` e envia `Authorization: Bearer <token>` nas chamadas.
- `create_article.py` / `create_articles_ig.py` — scripts/GUI para criar artigos em massa no Help Center usando um arquivo Excel.

## Arquitetura e fluxo de dados (essencial)

- Frontend -> Proxy Flask (`app.py`) -> Zendesk API. O proxy centraliza autenticação e evita expor credenciais diretamente ao cliente.
- `app.py` usa a função `zendesk_request(method, endpoint, **kwargs)` para montar `https://{ZENDESK_DOMAIN}.com{endpoint}` e autenticar com `("{ZENDESK_EMAIL}/token", ZENDESK_TOKEN)`.
- O frontend (`conecta.js`) faz um POST em `/login` (ver `app.py`) para obter um JWT (no repositório há credenciais de teste: `admin`/`123`) e usa esse JWT em chamadas subsequentes.

## Como rodar localmente (mínimo reproduzível)

- Variáveis de ambiente necessárias para o proxy (`app.py`):
  - `JWT_SECRET_KEY` — segredo para JWT usado pelo Flask-JWT-Extended
  - `ZENDESK_SUBDOMAIN` — subdomínio usado para montar as URLs Zendesk
  - `ZENDESK_EMAIL` — e-mail da conta API (usado como `{email}/token`)
  - `ZENDESK_API_TOKEN` — token da API Zendesk
  - opcional: `PORT` (padrão em `app.py` é 10000)
- Rodar o proxy (Python 3.8+):
  - Instale dependências listadas em `requirements.txt` (contém: flask, flask-cors, flask-jwt-extended, requests, python-dotenv).
  - Executar: `python app.py` (o servidor escuta por padrão em `0.0.0.0:10000`).

## Padrões e convenções do projeto

- Excel para criação em massa: as planilhas devem ter colunas `titulo` e `texto` (ver `create_articles_ig.py` e `create_article.py`). O código depende exatamente desses nomes de coluna.
- Payload padrão para criar artigo:

  ```json
  {
    "article": {
      "title": "...",
      "body": "...",
      "locale": "pt-br",
      "permission_group_id": <id>,
      "user_segment_id": null
    }
  }
  ```

- Conexões com Zendesk em scripts Python usam `HTTPBasicAuth(f"{email}/token", token)` (ex.: `create_article.py`). O proxy (`app.py`) usa tuple auth `(f"{ZENDESK_EMAIL}/token", ZENDESK_TOKEN)` na chamada `requests.request`.

## Integrações e pontos de atenção

- `conecta.js` espera um endpoint de login público em `/login` que retorna `{ "access_token": "<jwt>" }` e salva em `localStorage` com a chave `jwt_token` (ver trecho que chama `https://zendesk-proxy-na06.onrender.com/login`).
- O frontend chama as rotas proxy prefixadas com `/api/` — por exemplo `DELETE /api/community/posts/:id` mapeia para `DELETE /api/v2/community/posts/:id` em Zendesk (veja `app.py`).
- CORS: `app.py` registra CORS globalmente e também especifica `https://conecta.bcrcx.com` — ajuste conforme ambiente.

## Exemplos concretos (use quando modificar comportamento)

- Para deletar um post via proxy: rota `delete_post` em `app.py` mapeia `DELETE /api/community/posts/<post_id>` → Zendesk `/api/v2/community/posts/{post_id}`.
- Para criar artigos em massa: `create_articles_ig.py` tem a função `criar_artigos(path_excel)` que lê o Excel via pandas e `POST` para `/help_center/sections/{section_id}/articles.json`.

## Segurança & segredos (descobertas no repositório)

- Há tokens/credenciais hardcoded em alguns scripts de exemplo (`conecta.js`, `create_article.py`). Esses são sensíveis: não os exponha em commits públicos. Ao editar código, prefira buscar credenciais em variáveis de ambiente (o proxy já usa `python-dotenv`).

## Onde o agente deve ser cauteloso

- Não altere a forma como o proxy monta as URLs do Zendesk sem validar `ZENDESK_SUBDOMAIN`/`ZENDESK_EMAIL` — pequenas mudanças quebram todas as rotas.
- `create_articles_ig.py` usa GUI (CustomTkinter) e manipula arquivos locais; para automações preferir `create_article.py` como referência de payload/fluxo.

## Perguntas rápidas que você pode responder automaticamente

- "Onde o frontend obtém o JWT?" — `/login` em `app.py` (credenciais de teste `admin`/`123` em código).
- "Quais colunas o Excel precisa ter?" — `titulo` e `texto`.

Se algo estiver impreciso ou faltar contexto, diga exatamente qual arquivo/endpoint você quer que eu aprofunde e eu atualizo este guia.
