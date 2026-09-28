# 0028. Transporte `oci`: upstream como container efêmero fixado por digest

**Status:** Accepted — 28 set 2026.

## Contexto

Até aqui o Gatte servia um único transporte, `stdio`: o gateway spawna um
processo local e fala MCP pelo stdin/stdout dele. Uma implantação real não
quer os backends como processos soltos no mesmo host e com o mesmo acesso ao
sistema de arquivos que o processo que guarda todas as credenciais. Quer cada
backend numa imagem revisada, imutável, sem rede quando não precisa de rede,
e removida ao fim da conexão.

A linha interna de onde este repositório foi higienizado construiu esse
transporte depois da separação (14 set 2026), em quatro ADRs que nunca foram
publicados aqui e cujos números colidem com documentos diferentes deste
repositório (os `0016`–`0019` de lá não são os `0016`–`0019` daqui). Em 28 set
2026 o dono decidiu convergir as duas linhas num só código, o Gatte. Este ADR
traz as decisões daqueles quatro, reescritas sem nomes da implantação real,
em quatro seções. Cada seção mantém a numeração interna do ADR de origem
(item, decisão, via), porque é por ela que o código do adaptador cita:

| seção | trata de | era, na linha interna |
|---|---|---|
| §A | o transporte e o invólucro | `0016` |
| §B | o contrato de geração da imagem | `0017` |
| §C | o digest dentro da assinatura | `0018` |
| §D | onde o segredo fica visível sob podman rootless | `0019` |

Nada aqui muda um invariante do gateway: bind só em loopback (`0011`),
assinatura como condição para servir (`0003`, `0010`), quarentena por tool
(`0007`, `0013`), cofre por `sops` (`0005`), falha fechada (`0004`).

## §A. O transporte

### 1. `oci` roda *sobre* stdio

`registry.Transport` ganha `oci`. Uma entrada `oci` não tem `Command`: tem
`Image`, fixada por digest. O adaptador (`internal/gateway/oci`) monta o
processo filho

```
podman run --rm -i --log-driver=none --pull=never \
    --read-only --read-only-tmpfs=false --tmpfs=/tmp \
    --name NOME --network=POLÍTICA \
    --env NOME [--env NOME...] IMAGEM@sha256:DIGEST
```

e o entrega ao adaptador `stdio`, que fala MCP com ele como com qualquer
filho. É composição: o ambiente do filho construído do zero, a detecção de
upstream morto (`0024`) e o prazo por chamada (`0025`) são o mesmo código
nos dois transportes.

> **CORREÇÃO — 28 set 2026.** O invólucro acima está incompleto desde o
> `0034`. Todo `run` também leva `--cap-drop=all
> --security-opt=no-new-privileges` (fixas, no invólucro) e `--user=UID:GID
> --pids-limit=N --memory=M --cpus=C` (valores de `[oci]`, nunca 0 nem
> desligáveis), logo antes de `--name`. O `Args` da entrada pode repetir as
> duas fixas, mas não as quatro configuráveis. O usuário não-root do §B item
> 2 deixa de ser só promessa da imagem: o gateway impõe o uid.

O segredo nunca aparece em argv: `--env NOME` **sem** `=valor` faz o podman
ler o valor do próprio ambiente, e esse ambiente é o que o adaptador `stdio`
já constrói só com a lista mínima herdada mais os valores que o cofre
resolveu (§D, decisão 2).

O domínio não conhece podman. `internal/registry` ganha um campo de imagem e
a regra de digest; a tradução para argv mora no adaptador, e a escolha entre
`stdio` e `oci` mora no composition root (`cmd/mcp-gateway/dialer.go`), num
`switch` que recusa qualquer outro valor. O `Gateway` continua com um dialer
só.

### 2. Rejeitado: container de longa duração servindo HTTP

Exigiria um dialer HTTP, que não existe (`registry.ErrTransportUnsupported`),
e seria um segundo caminho, menos revisado, para uma credencial trafegar.

### 3. Política de rede por entrada, e quem pode usar `none`

1. A política de rede é o `Args` da entrada (`--network=VALOR`), coberto
   pela assinatura: alargar a rede de um upstream é um diff assinado e
   reaprovado, não uma flag num script.
2. O padrão é `none`: `Args` sem `--network` roda sem rede.
3. Quais valores além de `none` são legítimos não é decidido aqui; é
   política de egresso, com ADR próprio. Um backend que chama uma API
   (interna ou pública) precisa de rede, e para ele o caminho de exfiltração
   direto continua aberto. Isso não é pior que um processo `stdio`, que tem a
   rede do host inteira, mas não pode ser contado como controle ativo.

### 4. `--rm`, e o cold start

Nada do container sobrevive à conexão. O dial acontece no `Connect` e na
reconciliação, **um container por upstream por vida da conexão**,
compartilhado por todos os analistas; não é um container por chamada.

### 5. Onde o adaptador diverge do texto acima

- **(a)** O campo de rede é o `Args`, não uma coluna nova.
- **(b)** O invólucro obrigatório (as flags da primeira linha do bloco
  acima) é emitido pelo adaptador, sempre. O `Args` da entrada pode
  repeti-lo token a token, sem duplicar nada, e não pode acrescentar nada
  além de `--network=VALOR`: `-v …/podman.sock` e `--privileged` são
  recusados no `Dial` e, pelo mesmo teste (`dialTimeRefusal`), no `upstream
  register` e no `sign`.
- **(c)** Todo `run` leva `--name`, e `Close` roda `podman rm --force
  --ignore --time=0 NOME`. É a limpeza por nome, que cobre o podman que morre
  antes de cumprir o `--rm` (§D, via 7).
- **(d)** `--pull=never`: um digest que este host não construiu falha na
  hora, em vez de buscar a imagem num registro público no caminho crítico.
- **(e)** A seleção por transporte mora no composition root (item 1).
- **(f)** `--read-only --read-only-tmpfs=false --tmpfs=/tmp` entregam §B item
  3. Sem `--read-only-tmpfs=false` o podman monta `/var/tmp` e `/run`
  graváveis por conta própria.
- **(g)** Um `Dial` que falha pergunta ao runtime se a imagem existe, e a
  mensagem diz qual dos dois casos é.

## §B. O contrato de geração da imagem

Sete itens. Uma imagem que falhe em algum não deve ser registrada. A recusa
é de quem assina a entrada, não do gateway, e o verificador de contrato de
imagem da implantação mede os sete itens na imagem construída.

1. Base fixada por digest, nunca por tag.
2. Usuário não-root, sem shell de login (a imagem pode conter `/bin/sh`;
   "sem shell" é da conta, não da imagem).
3. Raiz somente-leitura em execução, com todo caminho gravável nomeado
   (`--tmpfs=/tmp`); entregue pelo invólucro, §A item 5(f).
4. Nenhuma credencial em build-arg nem em layer.
5. `ENTRYPOINT` que fala MCP por stdio, e só isso.
6. Dependências travadas por hash.
7. Labels OCI com fonte e commit; um rótulo de revisão sobre uma árvore suja
   é falso da imagem.

## §C. O digest dentro da assinatura

O digest é a única coisa que determina qual código roda dentro do container,
e sem registro OCI e sem cosign a assinatura Ed25519 da entrada é a única
âncora. Então ela cobre o digest.

**Diverge da linha interna, de propósito.** Lá o formato canônico inteiro
subiu de versão, e toda assinatura existente, inclusive a de entradas `stdio`
que não mudaram um byte, teve de ser refeita. Aqui:

- uma entrada **com** imagem (toda `oci`, e qualquer outra cuja linha tenha
  uma imagem) é codificada sob a tag `mcp-gateway/signer/canonical/v2-image`,
  com `Image` logo depois de `URL`;
- uma entrada **sem** imagem mantém os bytes `v1` exatamente, fixados por
  hash dourado em `TestCanonical_StdioEntryKeepsV1Bytes`. Nenhuma assinatura
  anterior a este ADR deixa de verificar.

As duas tags são o primeiro campo prefixado por comprimento, então bytes `v1`
e `v2-image` nunca coincidem. Uma assinatura `v1` não autentica uma entrada
com imagem, e uma linha `stdio` que ganhe uma imagem por escrita direta no
banco deixa de verificar em vez de manter a assinatura antiga
(`TestVerify_ImageInjectedIntoStdioRowBreaksSignature`). `Validate` recusa
imagem sem digest (`registry.validateImage`): uma assinatura sobre tag
atestaria um nome, e o nome aponta para o que foi construído por último.

O limite, dito: o digest prova que os bytes que rodam são os que estavam lá
quando o operador assinou. Não prova que esses bytes são bons. A confiança
na imagem é a confiança em quem a construiu.

## §D. Onde o segredo fica visível sob podman rootless

### Decisões

1. **Rootless, sob o usuário do gateway.** Sem daemon, sem socket de
   sistema. Quem lê o estado do container é quem já lia
   `/proc/<pid>/environ` do filho: o próprio usuário do gateway e root.
2. **`--env NOME`, sem `=valor`.** O valor vai do cofre para o ambiente do
   processo podman e dele para o container, e nunca atravessa argv. A regra
   de `registry` que recusa `=` em `EnvVarNames` passa a ter dois trabalhos.
3. **O invólucro mínimo inclui `--log-driver=none`.** Sem ele o `stderr` do
   backend, que o adaptador `stdio` descarta de propósito, seria gravado
   pelo driver de log do podman.

### As vias

1. **argv do podman — fechada** por construção (decisão 2).
2. **`podman inspect` — mitigada, residual aceito.** Enquanto o container
   vive, `Config.Env` guarda os valores num arquivo sob o storage do usuário
   do gateway. É a perda real deste transporte.
3. **Layers da imagem — fechada** por construção (§B item 4); quem detecta
   um `ENV TOKEN=` é a revisão de quem assina.
4. **Build-args — fechada**; se um build precisar de credencial, a resposta
   é `--secret`, nunca `--build-arg`, e isso emenda este ADR.
5. **Socket do runtime — mitigada.** O serviço socket-activado não é
   habilitado, e nenhum container recebe o socket montado: o `Args` não pode
   acrescentar flag nenhuma além de `--network` (§A item 5(b)).
6. **Logs do runtime — fechada** por `--log-driver=none`. Ressalva aceita:
   `~/.config/containers/containers.conf` do usuário do gateway pode mudar o
   nível de log e não é coberto por assinatura.
7. **Container morto em `podman ps -a` — mitigada.** Um podman que morre
   antes de cumprir o `--rm` deixa um container "exited" cujo `inspect` ainda
   tem `Config.Env`. Mitigação: limpeza por nome no `Close` (§A item 5(c)) e
   uma varredura no arranque da unidade. Os nomes que dirigem o runtime
   (`XDG_RUNTIME_DIR`, `HOME`, `TMPDIR`, `CONTAINERS_*`…) são recusados em
   `EnvVarNames` (`ErrRuntimeDirectingEnvName`). Senão o `run` e o `rm`
   rodariam em state dirs diferentes, e o `Close` devolveria sucesso sobre
   um container vivo.
8. **Arquivo de compose — fechada** por ausência.
9. **`/proc` do host — mitigada**, pela mesma fronteira da decisão 1.

## Consequências

- Uma implantação pode rodar cada backend como imagem revisada, sem rede
  quando não precisa, removida ao fim da conexão, sem mudar nada do lado do
  analista.
- O host precisa de podman rootless para o usuário do gateway. Uma
  implantação só com `stdio` não precisa de nada novo.
- Entradas `stdio` existentes continuam assinadas (§C).

## Compliance

- `internal/gateway/oci`: `TestBuildPlanAssemblesTheWrapperInOrder`
  (invólucro token a token), o teste de vazamento de credencial do pacote e
  `TestTheContainerRunsWithAReadOnlyRoot`, contra um podman falso que roda o
  servidor de laboratório `casemgmt`.
- `internal/signer`: `TestVerify_OCIEntryDetectsImageSwap`,
  `TestCanonical_StdioEntryKeepsV1Bytes`,
  `TestVerify_ImageInjectedIntoStdioRowBreaksSignature`,
  `TestCanonical_OCIAndStdioNeverCoincide`.
- `internal/registry/sqlite`:
  `TestMigrate_RetrofitsTheImageColumnOntoAPreOCIDatabase`.
- `cmd/mcp-gateway`: `TestUpstreamRegister_InvalidEntryIsRejected` (casos
  `oci`) e `TestRunUpstreamRegister_OCIEntryRoundTrips`.
