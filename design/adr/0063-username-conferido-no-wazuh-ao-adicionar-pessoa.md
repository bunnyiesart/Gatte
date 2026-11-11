# 0063. Username conferido no Wazuh ao adicionar uma pessoa

**Status:** Accepted — 11 nov 2026. Vale para o backend de contas
(`mcp-gateway admin -accounts`) e para os dois fronts. Anota `0038` (contas
do IdP) e `0040` (API de gestão). Não muda o IdP, o gateway nem a trilha.

## Contexto

O username de uma conta do Gatte é o nome que aparece nas linhas de
auditoria que vão para o SIEM (`0017`, `0056`). Quando ele não bate com o
nome que a mesma pessoa tem no Wazuh, o SIEM principal, quem investiga
precisa cruzar dois nomes para a mesma pessoa. O dono escolheu conferir o
username no Wazuh na hora de adicionar a pessoa.

## Decisão

1. **Opt-in em `config.toml`:** `[idp.wazuh_check]` com `url` (https, sem
   path), `user`, `password_name` (o NOME no cofre `[vault]`, nunca o valor)
   e `ca_file` opcional. Desligado quando `url` está vazio, que é o padrão.
   Uma chave sem `url` é recusada no load.
2. **Onde roda:** no `POST /v1/account-check` do socket de contas, que já é
   root e já lê o cofre. O backend faz um `GET
   /_plugins/_security/api/internalusers/USERNAME` com basic auth: 200 é
   `found`, 404 é `not_found`, qualquer outra coisa é `unchecked` com o
   motivo. Só pergunta quando o username não tem outro problema.
3. **Aviso, nunca bloqueio.** A resposta ganha `wazuh_user` (`status`,
   `message`); `ok` não muda. O operador vê a linha e segue se quiser — há
   contas legítimas que ainda não existem no Wazuh.
4. **Saída segura:** a senha vem do cofre a cada checagem e nunca aparece em
   resposta, log ou erro. Certificado verificado (TLS 1.2+, `ca_file` ou as
   raízes do sistema), nenhum redirect seguido, no máximo 5 s, pelo guard de
   egress compartilhado (`internal/egress`). Diferente de uma URL de backend,
   esta é escrita pelo root no `config.toml` e o indexer fica na rede do SOC,
   então faixas privadas são permitidas; loopback, link-local (metadados) e
   o resto do `RefuseAddr` continuam recusados. O `ca_file` passa pela mesma
   checagem de dono root que o `users_file`, porque decide para quem a senha
   vai.
5. **Contrato 1.11.0:** campo de resposta novo, aditivo, sem feature nova.

## Consequências

- Nomes iguais no Gatte e no Wazuh viram o caminho fácil, sem virar regra
  dura.
- Um Wazuh fora do ar custa ao assistente até 5 s e uma linha "Could not
  check Wazuh"; adicionar a pessoa continua funcionando.
- O usuário do indexer precisa de leitura nos usuários internos do plugin de
  segurança; é uma credencial a mais no cofre, com o mínimo de permissão.
- Só usuários internos do indexer são conferidos. Um Wazuh que autentica por
  LDAP/SAML responde `not_found` para quem só existe lá fora.
