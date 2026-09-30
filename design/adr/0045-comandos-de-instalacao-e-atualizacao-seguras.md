# 0045. Instalar e atualizar sem adivinhar: `check`, `backup`/`restore` e a guarda de schema

**Status:** Accepted — 30 set 2026. Implementado junto com este ADR: o
comando `check` (item 1), `backup` e `restore` com as units de exemplo
`examples/systemd/mcp-gateway-backup.{service,timer}` (item 2), a guarda de
schema em `internal/store` e a linha de boot da trilha (item 3), e
`docs/upgrade.md` (item 4).

## Contexto

A análise de qualidade de vida de 30 set 2026 olhou o Gatte do lado de
quem instala e de quem atualiza, e achou quatro buracos, todos do mesmo
tipo: o operador tinha de saber de cor uma regra que o binário conhece.

1. **Instalar é uma lista de donos e modos que ninguém confere.** O README
   ("Who owns what") diz: chave de assinatura de root, `0600`, ilegível
   para a conta de serviço; `config.toml` legível e não gravável por ela;
   chave age `0600` da conta de serviço. Nada verifica isso antes do
   `serve`. O erro de dono aparece como falha no boot (a chave age), ou não
   aparece nunca (a chave de assinatura legível pela conta de serviço, que
   é exatamente a falha que a separação existe para impedir). O `-wal` e o
   `-shm` que um `sudo mcp-gateway sign` deixa como root (o passo 4 do
   README avisa) só aparecem quando o `serve` não consegue abrir o banco.
   Um credencial que um backend declara e o cofre não tem só aparece no
   primeiro dial. E um `oci` sem faixa de subuid só aparece no primeiro
   `podman run`.
2. **Não há backup.** O banco SQLite guarda registro, assinaturas,
   aprovações, bloqueios, manutenção e a trilha. Copiar o arquivo com o
   `serve` rodando, em WAL, dá uma cópia que pode não abrir ou não ter as
   últimas linhas, e nada diz que a cópia é boa. Também não há volta: nada
   confere a cópia antes de ela substituir o banco vivo, e uma cópia com a
   trilha editada ou uma entrada alterada depois de assinada seria aceita
   em silêncio.
3. **Um binário não sabe se o banco é mais novo que ele.** Cada adaptador
   migra as suas tabelas de forma aditiva, e isso cobre o binário novo
   abrindo o banco velho. O contrário não é coberto: um rollback para o
   binário anterior roda as migrações dele sobre um schema que ele não
   conhece e segue gravando, e nenhum teste do binário anterior viu esse
   arquivo. Também nada na trilha diz qual build estava rodando quando:
   o log diz, mas o log roda e some; o batimento tem `boot`, não versão.
4. **Atualizar não tem receita.** O README fala em parar o `serve` para uma
   atualização (`maintenance on`, parar, trabalhar, subir, `maintenance
   off`), mas não diz o que fazer no meio, nem como voltar.

O que não pode mudar (os princípios do produto): o host continua leve
(nada sempre ligado, nenhum endpoint novo, nenhum webhook, nenhuma
atualização automática); o que não é coberto é dito junto com o que é; e
nenhum front ganha uma ação que a API de gestão não tenha.

## Alternativas

### Opção A — Documentar melhor e deixar a conferência com o operador

| Prós | Contras |
|---|---|
| Nenhum código novo. | É o estado atual. A lista já está escrita e a falha continua: uma regra que depende de o operador reler o README a cada host não é uma regra. |

### Opção B — O `serve` confere tudo no boot e recusa

| Prós | Contras |
|---|---|
| Nada roda num host mal montado. | O `serve` roda como a conta de serviço e não consegue ver a chave de assinatura de root nem o `config.toml` por dentro de um diretório que ela não lê: justamente as regras que mais importam ficam fora. E cada verificação nova vira uma causa nova de gateway que não sobe às 03:00, quando quem sabe consertar não está. |

### Opção C — Comandos de host, executados pelo operador, e uma guarda no único ponto que abre o banco (escolhida)

| Prós | Contras |
|---|---|
| `check` roda como root, antes do `serve`, e vê o que o `serve` não vê. `backup`/`restore` usam as mesmas conferências (integridade, cadeia, assinaturas) que o operador já roda à mão. A guarda de schema fica em `openStore`, por onde passam o `serve`, o `admin` e todo comando. | Um `check` que ninguém roda não protege nada; por isso o README o põe no passo 5 da instalação e `docs/upgrade.md` o põe duas vezes na atualização. A guarda só protege dali para frente: um binário anterior a ela não lê `user_version`. |

## Decisão

### 1. `mcp-gateway check`

`mcp-gateway check [-config FILE] [-user NAME] [-online] [-json]` confere,
sem gravar nada, e imprime uma linha por verificação com `PASS`, `WARN`,
`FAIL` ou `SKIP`, e em cada `FAIL` e `WARN` o comando que conserta:

- a configuração carrega e valida (o mesmo `config.Load` de todo comando);
- a conta de serviço: `-user`, ou o dono do diretório do banco, ou quem
  roda o `check` quando não é root; uma conta de serviço root é `FAIL`;
- `config.toml`: legível pela conta de serviço, e nem ele nem o diretório
  graváveis por ela;
- `signer.key_file`: de root, sem bit de grupo ou de outros, ilegível pela
  conta de serviço (`SKIP` sem `key_file`; `WARN` quando o arquivo não
  existe, porque a chave pode morar em outro host);
- `vault.age_key_file`: só do dono (o `sopsage` recusa outra coisa) e
  legível pela conta de serviço; `vault.secrets_file` legível por ela
  (`WARN` quando também gravável);
- `sops` no `PATH` (o do shell; o relatório diz que o do gerenciador de
  serviço pode ser outro);
- o banco: diretório gravável pela conta de serviço; banco, `-wal` e `-shm`
  graváveis por ela (o `-wal` de root do README); o schema (item 3); a
  cadeia da trilha; a assinatura de cada entrada contra
  `signer.trusted_keys` (inválida é `FAIL`; sem assinatura é `FAIL` com
  `require_signed` ligado e `WARN` sem ele; nenhuma entrada é `WARN`);
- `[audit.siem]`: a conta de serviço consegue acrescentar ao arquivo;
- o cofre decifra, neste processo, e contém todo nome de credencial que
  uma entrada declara. Nenhum valor é impresso, logado ou guardado; só
  nomes aparecem, como em todo o console;
- entradas `oci`: `podman` no `PATH` e, no Linux, uma faixa de pelo menos
  65536 ids em `/etc/subuid` e `/etc/subgid` para a conta de serviço;
- com `-online`, o documento de descoberta do IdP responde, com o mesmo
  `issuer` da configuração e um `jwks_uri`. É a única verificação que sai
  do host, e só quando pedida.

O banco é aberto em `mode=ro`, e nenhuma migração roda nele. Rodando como
root, o `check` faz primeiro, como root, todas as verificações de dono e
modo, e só então vira o dono do diretório do banco (o mesmo
`becomeDatabaseOwner` do `sign`, `0044`), antes de o SQLite abrir qualquer
coisa: uma abertura só-leitura de um banco WAL ainda cria o `-wal` e o
`-shm` quando eles não existem, e um par de root faria o `serve` não
subir, que é justamente o defeito que o `check` procura. Dali em diante,
o cofre incluído, tudo roda com os direitos da conta de serviço. Um banco
de schema mais antigo (todo host na primeira atualização para este
binário: `0`) pode não ter uma coluna que o adaptador lê; ele é lido por
uma cópia (`VACUUM INTO`) num diretório temporário privado, migrada lá
como o próximo `serve` migrará o banco vivo, lida e apagada. O arquivo
vivo nunca é gravado, e o `PRAGMA integrity_check` roda nele. As permissões são lidas dos bits de dono,
grupo e modo, como o kernel as aplica; ACL e MAC não são lidas, e o
relatório termina dizendo isso e o que mais não foi conferido.

Códigos de saída, os do projeto: 0 nenhum `FAIL` (avisos permitidos), 1 ao
menos um `FAIL`, 2 não conseguiu rodar (uso errado, `-user` desconhecido).
Uma configuração que não carrega é `FAIL`, código 1: é o achado que o
comando existe para dar.

### 2. `mcp-gateway backup` e `mcp-gateway restore`

`backup -out FILE|DIR [-keep N] [-json]` roda como a conta de serviço,
com o `serve` no ar (como root, vira antes o dono do diretório do banco).
Ele **não migra** o banco vivo, ao contrário de todo outro comando, que
passa por `openStore`: é o comando que uma atualização roda primeiro, com o
binário novo, enquanto o `serve` velho ainda roda sobre o arquivo; migrar
ali, ou carimbar o `user_version`, mudaria o arquivo sob o binário velho
antes da hora. A guarda de schema vale para ele também (um arquivo mais
novo é recusado), e um arquivo que não existe é recusado, não criado. A cópia é `VACUUM INTO`: uma transação de leitura, o
banco como estava naquele instante, num arquivo só, sem depender de `-wal`
e `-shm`. É escrita num diretório privado ao lado do destino, `chmod
0600`, conferida, e só então ligada ao nome final por hard link, que
recusa sobrescrever (rename, depois de olhar de novo, onde o sistema de
arquivos não tem link). Com um diretório, o nome é
`mcp-gateway-AAAAMMDDTHHMMSSZ.db` e `-keep N` apaga as mais antigas com
exatamente esse formato de nome, nada mais.

A conferência da cópia, lida sem migrar, porque o sha256 impresso tem de
descrever os bytes que ficaram (uma cópia de schema mais antigo é
conferida por uma segunda cópia, migrada, no mesmo diretório privado): `PRAGMA integrity_check`, o schema, a
cadeia da trilha (`VerifyChain`, a mesma do `audit -verify`) e as
assinaturas contra `signer.trusted_keys`. A saída dá o caminho, o tamanho,
o sha256, o schema, a contagem e o head da trilha, e a lista do que **não
está** na cópia, com os caminhos desta configuração: o `config.toml`, o
cofre, a chave age, a chave de assinatura, o IdP, a cópia SIEM da trilha,
o CA do `[connect]`, o TLS do proxy, as imagens dos backends `oci`. A chave
age e a de assinatura são segredos: a instrução é guardá-las offline e
separadas das cópias do banco. Uma cópia com a cadeia quebrada ou uma
assinatura inválida é mantida (é evidência) e o comando sai com 1,
avisando que o `restore` vai recusá-la.

`restore -in FILE [-expect-head HASH]` roda com o `serve` parado. Recusa, e
não muda nada, a menos que:

1. nada escute em `listen` (o `serve` segura esse endereço enquanto roda;
   trocar o arquivo sob um `serve` vivo o deixaria gravando no arquivo
   substituído, e o restore não teria acontecido);
2. a cópia passe no `integrity_check`;
3. o schema dela seja um que este binário conhece (item 3);
4. a cadeia da trilha dela verifique, e termine em `-expect-head` quando
   dado;
5. nenhuma entrada dela tenha assinatura que falhe contra os
   `signer.trusted_keys` **desta** configuração (`0006`: entrada alterada
   depois de assinada não tem leitura benigna; `0010`: a âncora está fora
   do arquivo). Entrada sem assinatura é só nota: o `serve` já não a serve
   com `require_signed`.

Rodando como root, o `restore` abre `-in` como root (a cópia pode ter
voltado de fora como de root) e então vira o dono do diretório do banco
antes de gravar qualquer coisa lá: a cópia de trabalho, o banco restaurado,
o `-wal` e a linha da cópia SIEM são todos da conta de serviço, sem
`chown` depois. As conferências rodam numa cópia de trabalho no diretório
do banco (que elas migram; o arquivo do operador nunca é tocado; o sha256
é dos bytes copiados, os mesmos que as conferências leem). Passando, o banco vivo
vai para o lado com `-wal` e `-shm` juntos, como
`DB.pre-restore-AAAAMMDDTHHMMSSZ`, e a cópia toma o lugar dele por rename
no mesmo diretório. Depois, uma linha de operador `(restore)` em
`(gateway)`, pelo mesmo `recordOperatorAction` dos outros comandos (SQLite,
JSONL, GELF), com o sha256 e o head da cópia e o caminho do banco guardado.

O que um restore custa, dito na saída e em `docs/upgrade.md`: o que foi
gravado depois da cópia sai da trilha restaurada. A cópia SIEM ainda tem, e
a cadeia dela passa a ter dois ramos a partir do head da cópia: as linhas
de depois e a linha `(restore)`. O `deploy/gatte-anchor-verify.sh` acusa
dois fragmentos. É verdade: a trilha voltou atrás, e a linha `(restore)` é
a explicação que fica registrada.

`backup` e `restore` são comandos de host, como `sign` e `upstream
register`, e não ações da API de gestão: um grava um arquivo no host, o
outro troca o banco sob um gateway parado. Nenhum front ganha esses botões,
e nenhum front deixa de ter uma regra por isso (`0040`).

### 3. A guarda de schema e a linha de boot

`store.SchemaVersion` é o schema que o binário grava, guardado no
cabeçalho do arquivo como `PRAGMA user_version`. Em `openStore`, **antes**
de qualquer migração, `store.CheckSchema` recusa um arquivo com número
maior, sem gravar nada, com a mensagem que diz o que fazer (rodar o binário
que o gravou ou restaurar a cópia de antes da atualização). Depois das
migrações, `store.RecordSchema` sobe o número, nunca desce. Como todo
caminho passa por `openStore` (`serve`, `admin`, todo comando do console),
todos recusam. Um arquivo sem número (`0`: novo, ou de antes da guarda) é
migrado como sempre foi. Começa em 1, em 30 set 2026.

Subir o número é obrigação de quem muda qualquer tabela.
`TestSchemaFingerprintMatchesTheVersion` compara o schema que `openStore`
produz com `cmd/mcp-gateway/testdata/schema-vN.sql` do número atual, e
falha até o número subir e a cópia nova ser gerada
(`GATTE_UPDATE_SCHEMA=1`). Sem isso a guarda passaria a mentir no primeiro
`ALTER TABLE` esquecido.

A primeira linha que todo `serve` grava na trilha é `(gateway)` →
`(boot)` → `(gateway)`, `allowed`, razão `boot: mcp-gateway VERSÃO, schema
N`, pelo gravador completo (SQLite, JSONL, GELF), antes do cofre e dos
backends: um boot que falha depois ainda fica registrado com a versão. A
versão é `buildVersion` (o `-X` do link) mais a revisão que o Go grava no
binário quando compilado de um checkout (`make build` não passa `-X`, e
"dev" sozinho não distingue dois binários), com `-dirty` quando a árvore
tinha mudanças. O `version` e a linha "starting" do log dizem o mesmo e o
schema. A linha usa só constantes do binário: nada do arquivo, do host ou
de uma requisição. Atribuída a `(gateway)`, fica fora do `$CALLS` do
`deploy/vm/gateway-serve-verify.sh` e da lista de analistas do console. O
formato das linhas JSONL não muda (`jsonl.Version` continua 5): é um
registro comum.

### 4. `docs/upgrade.md`

A receita: `maintenance on`, `backup` (na primeira atualização para este
binário o instalado ainda não tem `backup`, e o novo pode tirá-la antes da
troca, porque não migra o banco vivo), parar o `serve` (e o `admin`),
trocar o binário guardando o anterior, conferir o sha256 contra o da
máquina que compilou e o `version`, `check` com o binário novo (lê o banco
sem migrar), subir, ler a linha de boot e o resumo de início, `check` de
novo, `maintenance off`. E a volta: binário anterior, `restore` da cópia do
passo 2 com `-expect-head`, `check`, subir. Diz quando o `restore` é
obrigatório (schema do novo maior que o do anterior) e o que ele custa.

## Consequências

- Instalar ganha um passo que responde "está certo?" antes do `serve`, e
  cada resposta errada vem com o comando que a conserta. O passo 5 do
  README passa a ser `check`.
- O host continua leve: `check`, `backup` e `restore` rodam quando alguém
  roda; o timer de backup é do systemd, não um processo do Gatte, e a unit
  roda sem rede (`PrivateNetwork=yes`). Nenhum endpoint, nenhuma porta,
  nenhum webhook.
- Um rollback deixa de poder corromper o banco em silêncio, **a partir
  deste binário**. Os binários anteriores não leem `user_version`; o
  `docs/upgrade.md` diz para não rodar um deles sobre um arquivo que um
  binário novo abriu.
- A trilha passa a ter uma linha por boot. Um SIEM que contava linhas
  `allowed` como chamadas precisa filtrar `caller:"(gateway)"`, como já
  precisava desde `0032` e `0041`.
- Toda mudança de schema passa a vir com um número novo e uma cópia do
  schema em `testdata`. Duas mudanças em paralelo em ramos diferentes
  colidem nesse número no merge, de propósito.
- `restore` confia nos `trusted_keys` da configuração presente. Num host
  novo, uma configuração mais nova que a cópia (com a chave antiga já
  retirada) faz o restore recusar entradas legítimas; o documento manda
  restaurar a configuração da mesma data.

## O que não cobre

- ACL, SELinux/AppArmor e MAC do FreeBSD: o `check` lê só dono, grupo e
  modo.
- O `PATH` e os limites que o gerenciador de serviço dá ao `serve`: o
  `check` vê os do shell que o roda.
- Se cada backend responde: é o resumo de início do `serve` e a `0041`.
- Cópia para fora do host: o `backup` grava no disco local, e levar as
  cópias para outro lugar é trabalho do operador. Uma cópia no mesmo disco
  salva de uma atualização ruim, não de um disco perdido.
- O cofre, as chaves, a configuração e o IdP não entram na cópia, e o
  `restore` não os restaura.
- A detecção de `serve` vivo é o endereço de `listen` ocupado. Um `admin`
  ativado por socket com o banco aberto não é detectado; a receita manda
  parar o socket.

## Testes

- `internal/store`: arquivo novo é 0, `RecordSchema` sobe e nunca desce,
  `CheckSchema` recusa o número maior e diz o que fazer; `Snapshot`
  consistente com outro handle gravando, arquivo único, recusa
  sobrescrever; `IntegrityCheck` acusa uma página sobrescrita.
- `cmd/mcp-gateway/schema_test.go`: a impressão do schema contra
  `testdata/schema-v1.sql`; `openStore` grava o número; um arquivo de antes
  da guarda é migrado e carimbado; um arquivo um número à frente é recusado
  antes de qualquer migração (o binário N-1 diante do arquivo N); todo
  comando e o `serve` recusam; o `serve` grava exatamente uma linha de
  boot com a versão e o schema.
- `cmd/mcp-gateway/ops_dbowner_test.go`: o `check` lê a cadeia e as
  assinaturas de um banco de schema `0` sem gravá-lo nem carimbá-lo; o
  `backup` nunca migra nem carimba o banco vivo, e a cópia diz o schema de
  origem; `backup` recusa banco ausente (sem criá-lo) e mais novo; como
  root (simulado), `check`, `backup` e `restore` viram o dono do diretório
  antes de existir `-wal`, `-shm` ou cópia de trabalho, e o `check` não
  examina a chave de assinatura, a chave age nem a configuração depois de
  largar root.
- `cmd/mcp-gateway/backup_test.go`: cópia `0600` com sha256, cadeia e
  assinaturas certas e a lista do que não está nela; nunca sobrescreve;
  `-keep` só apaga nomes dele; restore de ida e volta (linhas de depois da
  cópia somem, linha `(restore)` com sha256 e caminho guardado, cadeia
  íntegra, cópia do operador intocada); recusas, sem mudar o banco vivo nem
  deixar sobra: trilha editada, head errado, entrada alterada depois de
  assinada, arquivo corrompido, schema mais novo, `serve` escutando, o
  próprio arquivo vivo; restore num host sem banco.
- `cmd/mcp-gateway/check_test.go`: as regras de permissão como o kernel as
  aplica; as regras da chave de assinatura e da chave age; uma implantação
  inteira com cofre real (resultados esperados por verificação, todo
  `FAIL`/`WARN` com conserto, nenhum valor de credencial no relatório, o
  banco byte a byte igual depois); credencial ausente do cofre; entrada sem
  assinatura com `require_signed`; schema mais novo; configuração que não
  carrega; `-user` desconhecido; `-wal` de root; `oci` sem `podman` e sem
  faixas de subuid/subgid; `-online` com emissor certo, errado e ausente.
- `internal/fitness`: a unit de backup grava onde lê e onde escreve.
