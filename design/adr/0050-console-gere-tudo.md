# 0050. O console gere tudo: APIs, assinatura, segredos e papéis pela tela, atrás de uma chave de configuração e só por túnel SSH

**Status:** Accepted — 09 out 2026.

**Revisão adversarial (09 out 2026), corrigida antes de publicar:** o
template da página de segredos se chamava `secrets.html`, e o `.gitignore`
do repositório (`secrets.*`) o deixava fora de qualquer checkout limpo;
virou `vault.html`. Um nome de backend como `-h` passava a checagem e fazia
o filho `sign` imprimir a ajuda, sair com 0 e virar uma linha de assinatura
falsa; o nome agora segue a gramática do registro, e o filho recebe `--`. O
cadastro assinava no mesmo clique (Decisão 5). A leitura do cofre e dos
papéis passou a exigir operador, como a escrita. O cofre só é editado,
nunca criado, e os destinatários vêm sempre dos metadados do próprio cofre.
`gatte console` ganhou trava e confere o processo antes de encerrá-lo.

## Contexto

O console web (`0036`, `0040`) já cobre pessoas, aprovação e revogação de
tools, bloqueios, auditoria, manutenção e quota. Ficaram de fora, por
decisão registrada:

- registrar, assinar e desregistrar um backend (`0036` §2, `0040`): assinar
  exige a chave de root, e desregistrar "é destrutivo demais para um botão";
- os papéis, que vivem num arquivo revisável e versionado (`0009`);
- os segredos: o binário mantém uma relação só de leitura com o cofre, e a
  rotação é `sops secrets.json` (`AGENTS.md`, "No rotate subcommand").
- `tool clear`, `reload` e `upstream redial` não tinham botão, sem decisão
  que o justificasse.

Na imagem Docker (`0049`) o console nem está exposto. O dono pediu (09 out
2026) um CRUD completo pela tela e decidiu:

1. **Acesso:** só por túnel SSH, como hoje. Da rede, nada novo é alcançável (Decisão 4 diz o que isso cobre).
2. **APIs:** o console registra, assina e remove.
3. **Segredos e papéis:** ambos editáveis pelo console.

## Decisão

### 1. Uma chave de configuração liga a gestão completa: `[admin] console_manages`

`console_manages = true` liga as operações abaixo na API de gestão e os
botões correspondentes no console. O padrão é `false`, e com ele uma
instalação em host continua exatamente como os `0009`, `0036` e `0040`
decidiram. A imagem Docker a liga, porque nela quem abre o console já é
root no contêiner que guarda a chave (`docker exec`), e a separação que o
`0036` protegia não existe ali.

Com a chave desligada, as operações novas respondem `feature_disabled`, e o
console não mostra os botões.

### 2. Operações novas na API de gestão (contrato 1.6.0)

No **socket do operador** (roda como a conta de serviço, dona do banco):

- `GET /v1/upstreams/{name}`: o detalhe de uma entrada, incluindo, para
  http, o descritor de auth e cada operação com método, caminho e classe.
- `POST /v1/upstreams`: registra uma API REST a partir do OpenAPI, por URL
  (buscada uma vez, com a guarda de egresso do adapter) ou pelo documento
  enviado. É o mesmo caminho do `upstream register -transport http`: mesma
  ingestão, mesmas recusas, mesmo relatório. Só http: stdio e oci continuam
  na CLI (`0034`).
- `DELETE /v1/upstreams/{name}`: desregistra. O corpo repete o nome, e o
  console pede que o operador o digite, porque a operação apaga as
  aprovações junto.
- `POST /v1/tools/clear`, `POST /v1/reload`, `POST /v1/upstreams/redial` já
  existiam; ganham botão.

No **socket de contas** (root), porque precisam do que só root tem:

- `POST /v1/upstreams/{name}/sign`: assina com a chave de root, por um
  processo filho `mcp-gateway sign`, que lê a chave como root e grava a
  assinatura como dono do banco, como faz na CLI.
- `GET /v1/secrets`, `PUT /v1/secrets/{name}`, `DELETE /v1/secrets/{name}`:
  os nomes do cofre, e gravar ou apagar um valor. O valor entra uma vez e
  nunca é devolvido, registrado nem logado. O cofre é decifrado e cifrado
  pelo `sops` pela entrada e saída padrão: o texto claro nunca vai para o
  disco.
- `GET /v1/roles`, `PUT /v1/roles`: o texto do arquivo de papéis. Um texto
  que a carga da configuração recusaria é recusado antes de ser gravado, com
  a mesma mensagem.

Cada mudança é uma linha de operador na trilha, como as demais (`0040`). A
linha de segredo leva o nome, nunca o valor.

### 3. Os papéis num arquivo próprio: `roles_file`

A configuração ganha a chave de topo `roles_file`. Quando presente, os
`[[role]]` e o `[group_to_role]` vêm desse arquivo, e o arquivo principal não
pode tê-los. O `reload` relê os dois.

Isso mantém o `0009`: os papéis continuam sendo um arquivo revisável, que
pode ser exportado e versionado. O que muda é que o console também o
escreve, depois de validar.

### 4. O console na imagem Docker, só por túnel SSH

O `mcp-gateway ui -manage-users` roda dentro do contêiner, em
`127.0.0.1:8091`. O Caddy o encaminha em HTTP simples na porta 8090 do
contêiner, sem TLS e sem reescrever o `Host`, e o `docker run` publica essa
porta só no loopback do host: `-p 127.0.0.1:8090:8090`. Quem quer o console
abre `ssh -L 8090:127.0.0.1:8090 VM` e roda `docker exec gatte gatte
console`, que gera um link de login de uso único.

As proteções do frontkit (`0036` §3) continuam todas valendo: `Host` de
loopback, link de uso único, sessão no caminho e no cookie, token de
formulário e `Origin` do próprio console.

O que a publicação em `127.0.0.1` do host garante, e o que não garante: da
rede, ninguém alcança a porta. Mas o Caddy escuta a 8090 em todas as
interfaces **do contêiner**, então outro contêiner da mesma rede Docker, ou
um processo do host pelo IP da bridge, chega a ela, e o `Host: 127.0.0.1`
que o frontkit exige é só um cabeçalho. Para esses, a barreira é o link de
uso único e a sessão que ele abre, que só o operador com `docker exec`
obtém.

### 5. Assinar é um segundo clique, na página que mostra o que se assina

Registrar pelo console não assina. A página de resultado mostra a URL, onde
a chave é injetada, se o descritor foi derivado do documento e cada
operação, e só ali há o botão de assinar. Uma assinatura no mesmo clique do
registro não atestaria que alguém olhou para o que ela cobre.

## Consequências

- **Quem tem o console pode assinar um backend.** Na imagem Docker isso já era
  verdade para quem tinha `docker exec`; o console não acrescenta poder, só
  o torna acessível pelo túnel. A aprovação de cada tool continua sendo o
  portão humano, e uma tool sensível continua exigindo `clear` e um papel
  `non_read` que a nomeie (`0048`).
- **O binário passa a escrever o cofre.** A frase do `AGENTS.md` ("a
  relação só de leitura com o cofre") vale agora só com
  `console_manages = false`.
- **Na imagem Docker, a trilha atribui as ações do console a `root`.** O
  kernel informa quem abriu o socket, e no contêiner é root. Saber qual
  pessoa estava no túnel SSH fica com o log do SSH da VM.

## Não cobre, e não se afirma coberto

- Registrar backends stdio ou oci pelo console.
- Acesso ao console pela rede, com login do Authelia: o dono escolheu o
  túnel SSH.
- Mais de uma sessão de console ao mesmo tempo: o frontkit tem uma sessão
  por processo, e `gatte console` gera um link novo, encerrando a anterior.
