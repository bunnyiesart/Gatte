# 0054. Papéis: UI estruturada que concede e revoga, sem regenerar o arquivo

**Status:** Accepted — 10 nov 2026. Detalha a seção Roles da aba "Users"
(`0051`). Supersede a parte de **edição** da página de papéis de `0050` §2/§3
(o "texto do arquivo de papéis" editado em bloco). Os portões — validar antes de
gravar, gravar não aplica, `reload` aplica — e `0009` ficam como estão.

*Revisto por `0061`:* a aba Users ficou só com People e Roles (sem Blocklist e
sem "Seen on the gateway"). A seção Roles decidida aqui não muda.

## Contexto

Os papéis vivem num arquivo TOML revisável e versionado (`0009`), e a decisão de
`0009` é explícita sobre **por que**: quem lê a configuração às 3h de um
incidente precisa do porquê ao lado da linha — qual papel tem qual tool, quem
aprovou, quando revisar. Esses comentários são carga: um `[[role]]` sem eles é
uma lista de permissões sem história.

`0050` §2 deu ao console um editor do **texto inteiro** do arquivo, validado
antes de gravar. O risco: qualquer fluxo que **regenere** o arquivo a partir da
estrutura em memória reescreve o TOML e **apaga os comentários** — exatamente a
carga que `0009` existe para preservar. Editar papel pela tela e manter `0009`
são objetivos em tensão se a tela regenerar o arquivo.

## Decisão

### 1. A tela é uma visão estruturada papel×tool

A seção Roles mostra uma matriz **papel × tool** (e `group_to_role`), lida de
`GetRoles` (`0050` §2). É a visão que faltava: quem pode chamar o quê, legível
sem ler TOML.

### 2. A escrita é cirúrgica, nunca uma regeneração

Conceder ou revogar uma tool a um papel é uma **edição pontual** do arquivo — a
menor mudança textual que acrescenta ou remove aquela entrada —, não uma
reescrita do arquivo a partir da estrutura. **A UI não regenera o arquivo de
papéis.** Os comentários de `0009` (aprovador, revisão, porquê), e todo o texto
que a edição não toca, sobrevivem byte a byte.

### 3. Validar → gravar → recarregar (de `0050`, reafirmado)

- Escrever **valida** com a mesma carga da configuração e recusa antes de gravar,
  com a mesma mensagem (`0050` §2); um arquivo que a carga recusaria não é
  gravado.
- **Gravar não aplica.** Um `reload` (na aba Servers, `serve_control` de `0044`)
  aplica; não há auto-reload por edição (`0050`, `0044`).
- Ler e escrever papéis exige operador e o socket de contas, e só com
  `console_manages` (`0050` §1, revisão adversarial).

## Consequências

- O operador concede e revoga sem editar TOML à mão, e a revisão em `git`
  continua sendo uma mudança pequena e legível, não um arquivo reescrito.
- Os comentários de `0009` ficam intactos — a propriedade que `0009` paga é
  mantida por construção, não por convenção.
- O editor de texto livre de `0050` §2 deixa de ser a superfície da tela; a
  mesma validação e o mesmo `PutRoles` continuam por baixo. Fica em aberto, para
  M1.5, a gramática exata da edição pontual sobre o TOML; esta ADR fixa a
  regra (cirúrgica, nunca regeneração), não a implementação.
