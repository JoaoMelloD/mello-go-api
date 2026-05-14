# Fase 1: A Construção (Blue Team)
Prazo: 14/05
## Missão: 
Desenvolver uma API REST minimalista chamada "O Cofre Digital". O sistema tem como objetivo permitir que usuários guardem anotações ou senhas secretas.
## Requisitos Funcionais Obrigatórios:
Sua API deve conter, no mínimo, os seguintes endpoints:


`POST /api/register:` Registra um novo usuário (nome, e-mail, senha).

`POST` /api/login: Autentica o usuário e retorna um token de acesso (ou inicia sessão).
**POST** /api/secrets: Cria uma nova anotação secreta, atrelando-a ao usuário logado. (Campos: título, conteúdo_secreto).
**GET** /api/secrets/{id}: Retorna os detalhes de uma anotação secreta específica via ID.
