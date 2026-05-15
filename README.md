# Fase 1: A Construção (Blue Team)
Prazo: 14/05
## Missão: 
Desenvolver uma API REST minimalista chamada "O Cofre Digital". O sistema tem como objetivo permitir que usuários guardem anotações ou senhas secretas.
## Requisitos Funcionais Obrigatórios:
Sua API deve conter, no mínimo, os seguintes endpoints:


`POST /api/register:` Registra um novo usuário (nome, e-mail, senha).

`POST` /api/login: Autentica o usuário e retorna um token de acesso (ou inicia sessão).

`POST` /api/secrets: Cria uma nova anotação secreta, atrelando-a ao usuário logado. (Campos: título, conteúdo_secreto).

`GET` /api/secrets/{id}: Retorna os detalhes de uma anotação secreta específica via ID para o usuário autenticado.

## Configuração

Crie um `.env` local com base no `.env.example`.

Variáveis obrigatórias:

- `JWT_SECRET`: segredo com pelo menos 32 bytes para assinar tokens.
- `SECRET_ENCRYPTION_KEY`: chave base64 de 32 bytes para criptografar segredos. Gere com `openssl rand -base64 32`.

Variáveis opcionais:

- `JWT_EXPIRATION_MINUTES`: duração do token entre 5 e 1440 minutos. Padrão: 60.
- `APP_ENV`: use `production` para habilitar HSTS.
- `ALLOWED_ORIGINS`: lista separada por vírgula para CORS explícito.
