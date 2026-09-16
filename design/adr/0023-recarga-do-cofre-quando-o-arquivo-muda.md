# 0023. O cofre relê o arquivo quando ele muda, e a detecção de rotação deixa de ser inerte

**Status:** Accepted — 15 set 2026.

## Contexto

O GAB-20 está registrado como **fechado na metade da detecção**: o
`WORKFLOW.md` diz que "divergence detection is built", o
`deploy/freebsd-jail.md` reproduz o aviso palavra por palavra, e o
`gateway.CredentialDrift` de fato roda uma vez por tick desde 10 set 2026.

**Ele não pode disparar.** Verificado no código, não deduzido:

- `sopsage.New` decifra uma vez e devolve `&Provider{secrets: secrets}`;
  `Resolve` lê desse mapa (`internal/vault/sopsage/provider.go`).
- `cmd/mcp-gateway/serve.go` chama `sopsage.New` **uma única vez**, no
  arranque.
- `CredentialDrift` re-resolve pelo mesmo `g.vault` de onde saíram os
  digests que ele compara.

Os dois lados da comparação saem do mesmo mapa congelado, então são sempre
iguais. O controle existe, roda, está documentado como funcionando, e é
inerte — que é pior do que não existir, porque um operador que lê "o gateway
avisa sobre isso agora" para de procurar.

O mesmo fato torna falsa uma segunda frase, escrita hoje mesmo no
`deploy/freebsd-jail.md`: *"uma re-discagem resolve credenciais de novo, então
trocar a entrada faz a rotação valer para aquele backend"*. Não faz: a
re-discagem chama `Resolve`, que lê do mapa congelado. **Só o restart fazia
uma rotação valer**, e nem o `Reconcile` da ADR-0020 mudava isso.

## Alternativas

### Opção A — Declarar inerte e corrigir os documentos

| Prós | Contras |
|---|---|
| Custo zero | O GAB-20 volta a ser aberto por inteiro, e a rotação de credencial fica sem nenhum sinal — que foi o defeito que abriu o GAB-20 ("eu rotacionei" e "o valor velho está em uso" eram o mesmo estado com duas crenças) |
| Honesto | Deixa código morto rodando a cada tick, ou exige removê-lo |

### Opção B — Reler o cofre a cada tick, incondicionalmente

| Prós | Contras |
|---|---|
| Simples de escrever e de explicar | Um subprocesso `sops` a cada intervalo, para sempre, decifrando o cofre com mais frequência do que hoje — mais janelas em que o texto puro existe, para nada, na esmagadora maioria dos ticks em que nada mudou |

### Opção C — Reler quando o arquivo mudar (escolhida)

| Prós | Contras |
|---|---|
| `sops` roda quando houve rotação, e só então; um `stat` por `Resolve` é o custo no caso comum | Mais estado no adaptador: carimbo do arquivo, lock, e um caminho de falha novo (relê e falha) |
| Faz três afirmações voltarem a ser verdade de uma vez: a detecção dispara, a re-discagem pega o valor novo, e o restart continua sendo o que vale para quem está conectado | `mtime`+tamanho não é prova criptográfica de mudança; uma rotação que preserve os dois passa despercebida |

## Decisão

**Opção C**, dentro do adaptador, sem mexer no port.

### 1. O `Provider` passa a ter um carimbo, e o consulta em cada `Resolve`

Guarda `mtime` e tamanho do arquivo cifrado. `Resolve` faz um `os.Stat`; se
o carimbo mudou, re-decifra, troca o mapa e responde do novo. Nada muda para
quem chama: `vault.Provider` continua com um método só, e nem o `Gateway`
nem o `CredentialDrift` sabem que isso existe.

Essa é a razão de a decisão caber aqui e não no `Gateway`: **é uma
propriedade do adaptador**, exatamente como a decisão de decifrar uma vez
era. O port sempre disse "resolva este nome"; ele nunca disse "resolva o que
você leu no arranque".

### 2. Falhar em reler não invalida o que já se tem

Se o `stat` ou o `sops` falharem, o `Resolve` **responde com o mapa
anterior**, sem erro. É a mesma regra que a ADR-0013 aplica à quarentena e
que a ADR-0020 passou a aplicar ao store de assinaturas: *falhar em medir
não é evidência de que algo mudou*. A alternativa — recusar-se a resolver —
transformaria um arquivo temporariamente ilegível numa frota que não sobe,
durante um incidente de disco.

**Responder com sucesso não é a mesma coisa que não dizer nada**, e a
primeira versão desta decisão errou justamente aí. Ela dizia "o adaptador
loga alto" e o adaptador não logava: ele não tem logger por desenho, e o
`Resolve` respondendo com sucesso significa que nenhum componente a jusante
via erro nenhum. O cofre podia ficar ilegível a noite inteira, o gateway
seguia servindo credenciais congeladas, e **nada em lugar nenhum dizia
isso** — o mesmo formato de defeito que esta ADR existe para consertar,
reintroduzido um nível abaixo, e encontrado por revisão no dia seguinte.

O adaptador agora recebe um `WithReloadErrorHandler`, e a raiz de composição
passa um que loga em Error com o caminho do arquivo. É **disparado na
borda**: uma linha quando a releitura começa a falhar, uma quando volta a
funcionar. O `Resolve` roda várias vezes por dial e uma por credencial por
tick de drift, então um handler por tentativa seriam centenas de linhas
idênticas num incidente — volume que treina o operador a filtrar a mensagem.

O que chega ao handler é seguro de logar por propriedade, não por promessa:
o erro do `os.Stat` carrega um caminho, o `decrypt` descarta o stderr do
sops e devolve só o status de saída, e o erro de JSON **não** é repassado,
porque mensagens de `encoding/json` citam o trecho que falharam em ler — que
aqui é material decifrado.

### 3. `mtime`+tamanho, e o que isso não cobre

É detecção de mudança, não integridade. Uma rotação que preservasse
`mtime` e tamanho (um `touch -r` deliberado, ou uma troca byte-a-byte de
mesmo comprimento com o mtime restaurado) passa despercebida. Aceito: quem
tem escrita no arquivo do cofre e cuida de preservar o carimbo já está
dentro do host que guarda o cofre e a identidade age, e o modelo de ameaça
do GAB-20 é operador rotacionando, não atacante escondendo rotação. Um hash
do conteúdo cifrado custaria ler o arquivo inteiro a cada `Resolve` e não
compraria nada contra esse mesmo atacante.

### 4. O que continua NÃO acontecendo

Nenhuma reconexão automática. Um upstream conectado segue com o valor que
recebeu no dial até alguém reiniciar — a metade do GAB-20 que continua
deliberadamente não construída, pelo motivo do canal de controle. O que
muda é só que a divergência passa a ser **visível**, que era a promessa
original.

> **EMENDA, 16 set 2026 — existe um terceiro caminho, e ele não estava
> escrito.** A ADR-0024 fez o gateway re-discar um backend cujo processo
> morreu, e uma re-discagem resolve o cofre de novo. Então um backend que
> **morre e volta** passa a rodar com a credencial atual, sem ninguém ter
> mandado rotacionar — e o aviso de drift daquele upstream desaparece junto,
> porque o digest guardado é reescrito no dial novo.
>
> Não é reconexão sob demanda: ninguém pode pedi-la, e a única forma de
> provocá-la é matar o backend. Mas "só um restart faz uma rotação valer"
> deixou de ser verdade para esse caminho, e um backend em crash-loop — os
> doze respawns por hora que a ADR-0024 orça — aplica rotações em silêncio.
> Quem lê a trilha vê `upstream gone`, não "a credencial em uso mudou".
>
> Registrado aqui, na ADR-0024 e em `deploy/freebsd-jail.md`, em vez de ser
> descoberto por alguém tentando entender por que o aviso de drift sumiu.

O que também muda, e precisa estar escrito porque uma frase do deploy já
dependia disso: **uma re-discagem passa a pegar o valor novo**. Ela acontece
quando a especificação da entrada muda (ADR-0020 item 1), não quando a
credencial muda — então não é um comando de rotação, é um efeito colateral
de substituir uma entrada. Com a recarga, essa frase passa a ser verdade;
sem ela era falsa desde que foi escrita.

## Consequências

**Impactos positivos:** o aviso do GAB-20 passa a disparar; o
`deploy/freebsd-jail.md` volta a descrever o sistema que existe; e uma
rotação seguida de `mcp-gateway serve` novo (ou de uma troca de entrada) usa
o valor novo sem depender de o processo ter subido depois do `sops`.

**Impactos negativos aceitos:**

- **Um `os.Stat` por `Resolve`.** Chamado uma vez por variável por dial, e
  uma vez por variável por tick no `CredentialDrift`. Irrelevante ao lado de
  spawnar um processo.
- **O texto puro passa a existir em memória mais de uma vez na vida do
  processo** — no arranque e a cada rotação detectada. É a consequência
  direta de detectar rotação; o mapa antigo é substituído e o anterior fica
  para o GC, sem zerar (Go não dá garantia de zerar string), o que já é
  verdade do mapa do arranque.
- **`mtime`+tamanho** com o buraco do item 3 escrito.

## Compliance

- [x] Automatizável? Sim.
- Onde vivem os testes, em `internal/vault/sopsage/provider_test.go`:
  - `TestResolveSeesARotationAfterTheFileChanges` — cifra, resolve, re-cifra
    com outro valor, resolve de novo e exige o valor novo.
  - `TestResolveKeepsTheOldValueWhenTheFileGoesUnreadable` — o item 2.
  - `TestResolveDoesNotReDecryptWhenNothingChanged` — conta invocações de
    `sops` por um stub de PATH, e é o teste que impede a Opção B de entrar
    por descuido.
  - `TestReloadFailureReachesTheHandler` — a releitura que falha chega ao
    operador exatamente uma vez, a recuperação também, e nem uma nem outra
    carrega o segredo.
  - E em `internal/gateway/gateway_test.go`,
    `TestCredentialDrift_NoticesARotationTheConnectionMissed`, que cobre o
    lado do `Gateway`. Ele passa com um fake e passaria com o adaptador real
    quebrado, que é precisamente por que a prova do adaptador vive aqui.
    (Esta linha nomeava `TestCredentialDrift_FiresWhenTheVaultValueChanges`,
    que nunca existiu — o Compliance de uma ADR é o primeiro lugar onde o
    próximo revisor procura a prova, e apontava para o vazio.)
- Quando roda: a cada build/CI.

## Notas

- Autor: bunnyiesart + Claude, 15 set 2026. O achado é de um agente de
  síntese, verificado à mão antes de virar decisão.
- Não confundir com a ADR-0018 (namespace plano do cofre, chaveado por nome
  de variável). Esta é sobre *quando* o conteúdo é lido, não sobre *como* é
  endereçado.
