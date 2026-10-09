# 0049. Gatte como imagem OCI: um `docker compose up`, quatro contêineres num só namespace de rede, e um comando de operador por tarefa

**Status:** Accepted — 09 out 2026.

**Correção de 09 out 2026 (0.2.0): um contêiner, não quatro.** A 0.1.0 saiu
como abaixo, com `compose.yaml` e quatro contêineres num namespace de rede
compartilhado. O dono recusou o resultado: instalar ainda exigia baixar dois
arquivos e editar um `.env`, e o pedido era "baixar a imagem e rodar". Na
0.2.0, Caddy e Authelia vão **dentro** da imagem do Gatte, e a instalação é
um `docker run` com `-e GATTE_DOMAIN` e um volume (`-v gatte:/gatte`). As
Decisões 1, 2 e 3 ficam abaixo como registro da 0.1.0; o que mudou:

- **Um processo por conta, num contêiner.** O entrypoint sobe o Authelia como
  `authelia`, o Caddy como `caddy` (porta 443 por `cap_net_bind_service` no
  binário, não como root), o gateway e o socket do operador como `gatte`, e
  o socket de contas como root, como numa instalação em host (`0038`). Se o
  Authelia, o Caddy ou o gateway sai, os outros param e o contêiner sai, para
  a política de reinício trazer o conjunto inteiro de volta. O loopback é o
  do próprio contêiner, então o `0011` continua intacto sem contêiner
  `pause`.
- **A base passa a ser Debian, não Alpine:** o binário de release do
  Authelia é ligado à glibc. Caddy e Authelia vêm das imagens oficiais, e
  toda imagem de origem é fixada pelo digest do seu índice multiarquitetura.
  O digest que o podman mostra é o de uma arquitetura só, e fixá-lo teria
  quebrado o build amd64.
- **Um volume, `/gatte`.** As configurações (`GATTE_DOMAIN`, `GATTE_PORT`,
  `GATTE_TLS`, `GATTE_ACME_EMAIL`) são gravadas nele na primeira execução, e
  um contêiner recriado sem os `-e` (um upgrade) as lê de volta.
- **Os papéis ficam no volume**, editados por `gatte roles edit` ou
  carregados por `gatte roles set < roles.toml`. Um arquivo que o gateway
  recusa no `reload` não é aplicado: o anterior volta. Continua sendo um
  arquivo revisável e versionável, como o `0009` pede; o que mudou é onde ele
  mora.
- **A conta de arranque desabilitada é permanente.** Na 0.1.0 o primeiro
  `gatte user add` a apagava. O teste da 0.2.0 apanhou o defeito: apagar a
  última pessoa deixava o arquivo de usuários vazio, e o Authelia não subia
  mais. Agora ela nunca é apagada, todo arranque a recoloca se o arquivo
  ficar vazio, e `gatte user list` não a mostra.
- **O teste ponta a ponta vai dentro da imagem**: `gatte selftest`. Ele
  passa pelos nomes públicos e pelo TLS de dentro do contêiner, não pela
  porta publicada no host.
- **O OpenAPI chega pela URL ou pela entrada padrão** (`-openapi -`), sem
  diretório no host.

**Estado de implementação (09 out 2026, 0.2.0):** `deploy/docker/`
(Dockerfile, `entrypoint.sh`, `lib.sh`, o comando `gatte`, `selftest.sh`, os
modelos de configuração e um `compose.yaml` opcional de um serviço), o
`.dockerignore` da raiz e o workflow `.github/workflows/image.yml`, que
publica `ghcr.io/bunnyiesart/gatte`. Na 0.1.0 eram também `compose.build.yaml`,
`.env.example` e `smoke.sh`, removidos na 0.2.0.

## Contexto

O guia de instalação do `README.md` tem sete passos e cerca de trinta
comandos: conta de serviço e diretórios, chave de assinatura, configuração
editada à mão, cofre com `age-keygen` e `sops`, registro, assinatura, `check`,
`serve`, revisão e aprovação. A isso se somam, fora do Gatte, um IdP OIDC e um
proxy TLS. O dono pediu (09 out 2026) que tudo isso se resolva por Docker:
puxar uma imagem e subir.

Três decisões do dono, de 07 out 2026, delimitam o desenho:

1. **TLS por um proxy ao lado, não pelo Gatte.** O `0011` (o gateway só escuta
   em loopback, sem override) fica intacto.
2. **A imagem serve só backends REST** (`-transport http`, `0047`/`0048`). Não
   há podman dentro da imagem, então nem `oci` nem `stdio` com credencial.
3. **Ordem:** Passo 4 do `0048` (ingestão OpenAPI) antes desta imagem; os
   botões do console (`tool clear`, `reload`, `redial`) depois.

O que impedia "só puxar uma imagem", levantado contra o código:

- `listen` aceita só loopback (`config.RequireLoopbackBind`). Num contêiner,
  o loopback é do contêiner, e `-p` não o alcança.
- O IdP é obrigatório, em https, e descoberto no boot.
- `sops` é chamado como CLI (`0005`); a chave age tem de ser só do dono.
- `config.toml` e `signing.key` são de root e o serviço não pode escrevê-los
  (`check` recusa o contrário).
- Não havia `init`: upstreams, assinaturas e aprovações entram por comandos
  imperativos.

## Decisão

### 1. Um namespace de rede, quatro contêineres

`compose.yaml` sobe `net`, `init`, `authelia`, `caddy` e `gatte`. Todos, menos
`net`, usam `network_mode: service:net`. Assim `127.0.0.1` é o mesmo para os
quatro: o Caddy alcança o gateway em `127.0.0.1:8080` e o Authelia em
`127.0.0.1:9091`, e o `0011` continua valendo sem nenhuma linha de código.

O dono do namespace é `net`, um contêiner `pause` (`registry.k8s.io/pause`), e
não o gateway. Se o gateway fosse o dono, cada reinício dele (por exemplo,
quando o IdP ainda não respondia no boot) arrancaria a rede de baixo do Caddy e
do Authelia. E `net` não usa a imagem do Gatte: a primeira versão usava, e o
teste apanhou que um rebuild da imagem pedia para recriar `net`, o que o podman
recusa enquanto outros contêineres usam o seu namespace. Com uma imagem que
nunca muda num upgrade, `docker compose up -d --build` troca só o Gatte.

`net` também publica as portas e declara os `extra_hosts` que fazem o nome
público do IdP resolver para o Caddy dentro do namespace, para o `serve`
descobrir o issuer pelo mesmo URL que os analistas usam.

### 2. Primeira execução idempotente: `gatte-entrypoint init`

O serviço `init` roda antes de tudo (`service_completed_successfully`) e cria
só o que falta:

- a chave de assinatura (root, `0600`, num diretório `0700`) e a sua metade
  pública;
- a chave age (do serviço, `0600`) e um cofre vazio cifrado com sops;
- com `GATTE_TLS=internal`, uma CA privada e um certificado para os dois nomes,
  reemitido quando os nomes mudam ou faltam menos de 30 dias;
- os segredos do Authelia e a sua chave RSA de assinatura OIDC;
- uma conta **desabilitada** de arranque no arquivo de usuários, com senha
  aleatória que não é guardada. O Authelia recusa subir com zero usuários, e o
  socket de contas que grava as reais só existe depois do gateway. O primeiro
  `gatte user add` a apaga pela API, e `gatte user list` não a mostra;
- `base.toml`, `configuration.yml` do Authelia e o `Caddyfile`, a partir de
  quatro valores do `.env`.

Só `GATTE_DOMAIN` é obrigatório. `GATTE_PORT` entra em todo URL quando não é
443, porque issuer e audience são comparados como texto.

### 3. A cada arranque: `gatte-entrypoint serve`

Monta `config.toml` = `base.toml` + `config/roles.toml` (+ `config/extra.toml`),
de root, legível pelo grupo do serviço. Instala a CA privada no repositório do
sistema do contêiner, sobe os dois sockets da API de gestão (o do operador
como o serviço, o de contas como root, cada um reiniciado se sair), espera o
IdP responder, roda `check`, e só então faz `exec` do `serve` como o usuário
`gatte` (uid 10001) sob `tini`.

### 4. Os papéis continuam num arquivo revisável

`config/roles.toml` fica no host, ao lado do `compose.yaml`, por bind mount.
Pode ser revisado e versionado, como o `0009` pede. O `gatte api add` só
acrescenta `NOME = ["*"]` sob `[role.grants]` do papel indicado (`analyst` por
padrão), na vista do operador. Um `"*"` nunca alcança uma tool sensível
(`0048` Decisão 5).

### 5. Um comando de operador por tarefa: `gatte`

`docker compose exec gatte gatte ...` compõe os comandos do próprio
`mcp-gateway` e a API de gestão, cada um rodando com a conta que exige:

- `api add` registra, assina e concede; `api approve` mostra o conjunto inteiro
  e aprova exatamente o manifesto mostrado, depois de um "y" no terminal ou
  de `-yes`; `clear` libera uma tool sensível.
- `secret set` lê o valor do terminal sem eco e o grava no cofre, por um
  arquivo temporário em `/dev/shm` apagado na saída; nenhum valor passa por
  argumento de processo.
- `user add/list/reset/rm` e `connect` falam com os sockets da API de gestão
  por `curl --unix-socket`, como root. As contas continuam saindo só pelo
  socket de root (`0038`, `0040`).

Nenhum comando aprova sozinho. A quarentena continua a mostrar cada definição
antes da aprovação.

### 6. O teste de fumaça acompanha a entrega

`deploy/docker/smoke.sh` roda no host, contra a pilha de pé, como um analista
faria. Cria uma pessoa temporária e entra no Authelia pelo fluxo de código com
PKCE do cliente público, com curl no lugar do navegador. Abre uma sessão MCP com o token,
chama uma tool segura (tem de responder) e uma sensível (tem de ser recusada),
e apaga a pessoa. A senha e o token ficam em variáveis e num diretório
temporário privado.

### 7. Publicada em `ghcr.io/bunnyiesart/gatte`, construída só pelo CI

A imagem é construída e publicada pelo workflow `.github/workflows/image.yml`,
a partir da árvore pública, nunca de um laptop: o que sai é exatamente o que o
repositório diz, sem arquivo local, credencial local ou o que um
`.dockerignore` precisaria lembrar de excluir. O workflow roda `go vet` e
`go test ./...` antes, gera linux/amd64 e linux/arm64, e publica com SBOM e
atestado de proveniência. Cada action de terceiro está fixada por commit, não
por tag que o mantenedor pode mover.

Tags: `vX.Y.Z` publica `X.Y.Z`, `X.Y` e `latest`; o `main` publica `edge`.

Instalar passa a ser baixar `compose.yaml` e `.env.example` e rodar
`docker compose up -d`. Quem quer compilar do código soma `compose.build.yaml`.

## Verificação da 0.2.0 (09 out 2026)

Numa VM podman 6.1.2 (arm64), sem nenhum arquivo no host:

1. `docker run -d --name gatte -p 8443:8443 -e GATTE_DOMAIN=gatte.localtest.me
   -e GATTE_PORT=8443 -v gatte:/gatte gatte:local`: subiu de primeira, com
   `check` sem falhas.
2. Pelo `docker exec`: segredo pela entrada padrão, a Petstore registrada pela
   URL do OpenAPI, aprovação com `-yes`, e `gatte selftest` com todas as
   verificações passando.
3. Cada processo roda com a sua conta (lido de `/proc`). O segredo aparece 0
   vezes no log.
4. `docker stop` parou os três em menos de 2 s.
5. Recriado sem nenhum `-e`, o contêiner leu as configurações do volume. O
   mesmo teste apanhou o defeito da conta de arranque: o arquivo de usuários
   tinha ficado vazio depois do `selftest`. Corrigido; o arranque seguinte
   consertou o volume sozinho.
6. `gatte roles set` com uma chave inválida foi recusado e o arquivo anterior
   voltou; com um papel `non_read` válido foi aplicado, e o `clear` passou.
7. `-openapi -` registrou a API a partir da entrada padrão.
8. Com `GATTE_PORT=443`, o Caddy abriu a 443 como usuário `caddy`.

## Verificação da 0.1.0 (09 out 2026)

Numa VM podman 6.1.2 (arm64), com `docker compose` 5.2, do zero (volumes e
`config/` apagados), com `GATTE_DOMAIN=gatte.localtest.me` e `GATTE_PORT=8443`:

1. `docker compose up -d --build`: o `init` criou todas as chaves, o cofre, a
   CA e os segredos do Authelia; `check` passou com 0 falhas; o `serve` subiu.
2. Do host: metadados RFC 9728 e issuer corretos, e um 401 com o desafio
   OAuth numa chamada anônima.
3. `gatte secret set`, `gatte api add` com a Petstore pública
   (`petstore3.swagger.io`, documento buscado por URL) e `gatte api approve
   -yes`: 18 tools (8 seguras, 10 sensíveis), uma operação pulada por não ser
   JSON, entrada assinada, concessão escrita em `config/roles.toml`.
4. `./smoke.sh petstore findPetsByStatus addPet '{"query_status":"available"}'`:
   todas as verificações passaram. A analista viu só as 8 seguras, a chamada
   voltou 200 da API real, e `addPet` não foi listada nem servida.
5. O valor do segredo aparece 0 vezes nos logs de todos os contêineres.
6. `gatte clear petstore addPet` liberou depois de um papel `non_read` nomeá-la;
   `deletePet`, que nenhum papel nomeia, foi recusada com a instrução do que
   falta.
7. `docker compose down` seguido de `up` manteve contas, segredos e chaves.

A Petstore expôs um defeito do Passo 4: a operação `DELETE /pet/{petId}`
declara como parâmetro o próprio cabeçalho da chave, e a ingestão recusava o
documento inteiro. A correção está no `0048`, nota de 09 out 2026.

## Consequências

- **O caminho de instalação cai de cerca de trinta comandos para seis:**
  `.env`, `up`, `secret set`, `api add`, `api approve`, `user add`.
- **A separação root/serviço continua dentro do contêiner.** `check` roda a
  cada arranque e recusa subir se ela quebrar.
- **O Authelia passa a fazer parte da entrega.** A configuração vem da que roda
  na VM Linux de teste do projeto, com um único cliente OIDC, o do Claude Code
  (público, PKCE S256).
- **A CA privada é uma CA de verdade.** Quem tiver `ca.key` emite certificados
  em que os analistas confiam. A chave fica no volume `gatte-etc`, de root, e
  nunca é montada no Caddy.

## Não cobre, e não se afirma coberto

- **Backends `oci` e `stdio`.** A imagem não tem podman; um MCP pronto em
  contêiner continua no caminho do `README.md`.
- **O console web** (`mcp-gateway ui`) não é exposto. Ele escuta em loopback
  com um link de login de uso único, e publicá-lo atrás do Caddy é outra
  decisão. Os sockets da API de gestão já sobem, então o próximo passo é só o
  front.
- **Rotação do JSONL para o SIEM** e o envio GELF: a seção `[audit.siem]` vai
  em `config/extra.toml`, sem rotação.
- **Backup:** os volumes `gatte-etc` e `gatte-data` são o estado inteiro;
  `mcp-gateway backup` existe, mas não está ligado a um timer aqui.
- **Uma CA com restrição de nomes.** A CA privada não usa `nameConstraints`.
