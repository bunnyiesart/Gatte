# 0010. Âncora de confiança: chaves públicas confiáveis na configuração

**Status:** Accepted

## Contexto

A revisão de 09 set 2026 encontrou, e **provou explorável**, um defeito na
verificação de assinatura que o `0006` construiu:

`signer.Verify(entry, sig)` verifica a assinatura usando `sig.PublicKey` —
a chave que viaja **dentro da própria linha de assinatura**, lida de
`entry_signatures.public_key`. Nada em lugar nenhum diz quais chaves são
confiáveis: `config.Signer` tinha apenas `KeyFile` e `RequireSigned`.

O comentário da função dizia isso em voz alta, tratando como virtude:

> Verify é uma função livre, não um método de Signer, porque a verificação
> precisa apenas da chave pública que viaja dentro de sig.

Verificar uma assinatura contra uma chave fornecida por quem forneceu a
assinatura não prova autenticidade nenhuma. Prova apenas consistência
interna: que aquele par (chave, assinatura) foi gerado junto. Qualquer um
gera um par desses.

### A prova

Reproduzido com o código real, não deduzido:

1. Adulterar a entrada (`command` → `/tmp/evil`) e apresentar a assinatura
   legítima: **recusado**. Essa metade sempre funcionou.
2. Adulterar a entrada, gerar um par Ed25519 novo, assinar a entrada
   adulterada com essa chave nova e gravar as duas coisas na linha de
   assinatura: **aceito**.

Ou seja: um atacante com escrita no banco reescreve `upstream_servers`,
reescreve `entry_signatures`, e o gateway spawna `/tmp/evil` injetando
nele todas as credenciais que a entrada nomeia. `require_signed = true`
não ajuda — a entrada *está* assinada. `mcp-gateway upstream list` imprime
`SIGNED: yes`.

### Por que isso é grave especificamente aqui

O `0006` item 3 justifica incluir `Name` no hash canônico citando
nominalmente o atacante: *"plausível entre um `casemgmt` legítimo e um
`casemgmt-staging` criado por **quem tenha escrita no banco**"*. Contra
exatamente esse ator, o controle inteiro não oferecia resistência.

E as duas tabelas moram no **mesmo arquivo SQLite** (`main.go` migra as
quatro no mesmo handle), então "escrita no registro" e "escrita nas
assinaturas" são a mesma permissão. Não há degrau entre uma e outra.

## Decisão

**As chaves públicas confiáveis vivem no arquivo de configuração, e a
verificação passa a ser feita contra elas — nunca contra a chave que
acompanha a assinatura.**

```toml
[signer]
trusted_keys = [
  "K7f3...=",   # base64 dos 32 bytes da chave pública Ed25519
]
```

### 1. Por que na configuração, e não no banco

O `0006` item 1 tirou a chave *privada* do SQLite porque o `0001` diz que
o banco embarcado nunca guarda segredo. A observação que faltou é
complementar e não tem nada a ver com sigilo: **uma âncora de confiança
guardada ao lado daquilo que ela autentica não é âncora.** A chave pública
não é segredo — é justamente por isso que ela pode ficar em um arquivo
versionado e revisado — mas precisa estar **fora do raio de dano** de
quem adultera o que ela atesta.

Isso é o mesmo raciocínio do `0009`, que colocou papéis no arquivo
versionado e não em tabela: mudar quem pode chamar o quê deve ser um diff
revisado. Mudar em quem o gateway confia para assinar entradas é a decisão
de política mais forte que existe neste sistema; ela merece pelo menos a
mesma cerimônia.

### 2. `sig.PublicKey` continua existindo, mas perde autoridade

O campo não sai da linha de assinatura: ele é útil para *diagnóstico* —
dizer ao operador **qual** chave assinou, e detectar que uma entrada foi
assinada por uma chave que já não é confiável. O que ele deixa de ser é
insumo da decisão. A verificação usa as chaves confiáveis configuradas.

Uma assinatura cuja chave não está no conjunto confiável é **recusada como
inválida**, não tratada como ausente. Ela é evidência positiva de que
alguém assinou esta entrada com uma chave que este gateway não reconhece,
e isso não tem leitura benigna — mesma lógica que o `0006` aplica a uma
assinatura que não confere.

### 3. `require_signed` sem `trusted_keys` é contradição, e falha no arranque

Exigir assinatura sem ter contra o que verificar é pedir uma garantia
impossível. `Validate` recusa a combinação, com mensagem que diz o que
fazer. Falhar no arranque, na frente do operador que acabou de editar o
arquivo, é o padrão que o `0009` já estabeleceu.

Pelo mesmo motivo, `gateway.New` passa a recusar `RequireSigned` com
`Signatures == nil` — hoje inalcançável pelo `cmd`, mas é a forma exata
de "padrão de segurança desligado em silêncio" que este projeto existe
para não repetir.

### 4. `require_signed = false` com `trusted_keys` vazio: assinada é recusada, sem assinatura é servida

Este caso não estava previsto acima e foi decidido durante a implementação.
Registrado aqui porque decisão que só existe no código é exatamente o que
a disciplina de ADR deste projeto proíbe.

A combinação é coerente ("assinatura está desligada"), mas o resultado lê
ao contrário na primeira leitura: **assinar uma entrada faz ela parar de
ser servida**, enquanto não assinar nada funciona.

Fica assim mesmo, e a razão é a mesma do `0006` item 4: uma assinatura
presente é uma **afirmação**. Não conseguir checar uma afirmação não é o
mesmo que não ter afirmação nenhuma — é não saber. Servir assim seria
exatamente o estado "não verificado, mas servido do mesmo jeito", que é a
classe de falha que este projeto encontrou em cinco dos seis candidatos.
Não verificável fica mais perto de inválida do que de ausente.

O custo é o incentivo perverso: um operador experimentando aprende "não
assine". Mitigado por ser barulhento, não silencioso — o `Connect` avisa
explicitamente quando o conjunto confiável está vazio, e o erro por entrada
diz qual chave assinou e que ela não está em `trusted_keys`. A correção é
uma linha de configuração, e a mensagem diz qual.

Se um dia se preferir que essa combinação tolere entradas assinadas, isso é
**abrandar o item 2 de propósito** e merece emenda a este ADR — não uma
mudança silenciosa no código.

### 5. Ergonomia, senão ninguém liga

Um controle que dá trabalho para ligar fica desligado. `mcp-gateway sign`
passa a imprimir a linha pronta para colar quando a chave que ele acabou
de usar não está em `trusted_keys` — o operador copia, cola, reinicia.

## Consequências

**Impactos positivos:** o controle passa a valer contra o ator que o
`0006` nomeia. Escrita no banco deixa de bastar: forjar uma entrada servida
passa a exigir também a chave privada de alguém em `trusted_keys`, que por
`0006` item 1 mora fora do banco, em arquivo `0600`. A lista confiável
sendo múltipla também dá rotação de chave sem janela de indisponibilidade
— adiciona a nova, re-assina, remove a velha.

**Impactos negativos aceitos:** mais um campo obrigatório na configuração
quando `require_signed` está ligado (que é o padrão desde a Fase 6), então
**toda configuração existente que exija assinatura passa a precisar de
edição**. Isso é uma quebra deliberada, e o momento é o melhor possível: o
gateway nunca rodou fora de teste, então não há implantação para migrar.
Um operador que perca todas as chaves privadas confiáveis precisa editar a
configuração para voltar a servir — correto, e é o mesmo custo de qualquer
âncora de confiança de verdade.

**O que isto não resolve:** o gateway continua confiando no banco para
saber *que entradas existem*. Uma entrada legítima **removida** do
registro por quem tem escrita simplesmente deixa de ser servida — negação
de serviço, não execução de código. Aceito: é uma classe muito menos grave,
e detectável pela ausência.

## Compliance

- [x] Automatizável? Sim.
- Mecanismo: o teste de forja — adulterar a entrada, re-assinar com uma
  chave não confiável, e exigir recusa. Escrito primeiro contra o código
  antigo, onde **passa a forja** (confirmado), para que o teste seja
  evidência e não decoração. Mais: `require_signed` sem `trusted_keys`
  recusado no `Validate`, e `gateway.New` recusando `RequireSigned` com
  store nula.
- Onde vive: `internal/signer/signer_test.go`,
  `internal/config/config_test.go`, `internal/gateway/gateway_test.go`.

## Notas

- Autor: Claude, 09 set 2026, a partir da revisão de pendências.
- Corrige um defeito de `0006`, que continua válido em tudo o mais — a
  separação de arquivo e tabela, o `Name` no hash canônico e a codificação
  TLV seguem como escritos. O que muda é **contra o que** se verifica.
- Depende de `0001` (banco nunca guarda segredo), `0006` (o que é
  assinado) e `0009` (política mora em arquivo versionado).
