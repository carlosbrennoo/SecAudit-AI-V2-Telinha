# SecAudit AI - v2

Evolução do SecAudit AI v1, agora com interface gráfica completa. A lógica de auditoria é a mesma da v1 - paralela, local, sem custo - mas agora com uma tela de login, cards de progresso em tempo real e relatório exibido direto na janela.

---

## O que mudou da v1 pra v2

**Interface gráfica com CustomTkinter**
Na v1 tudo rodava no terminal. Na v2 tem uma tela de login, cards visuais pra cada módulo que ficam amarelos enquanto analisam e verdes quando concluem, barra de progresso e aba de relatório.

**Tela de login segura**
As credenciais AWS são digitadas na interface e apagadas da memória assim que a auditoria termina. Nada fica salvo em disco além do `.env`.

**Dois arquivos separados**
O projeto foi dividido em `app.py` (interface) e `audit.py` (lógica de auditoria), deixando o código mais organizado e fácil de manter.

**Escolha do tipo de relatório**
Na tela de auditoria você escolhe entre Detalhado ou Resumido antes de iniciar.

**Botão de salvar**
O relatório pode ser salvo em qualquer pasta com nome gerado automaticamente por data e hora.

---

## O que ele verifica

A auditoria roda em **todas as regiões habilitadas** da conta e cobre 19 módulos, com severidade padronizada (`CRITICO`, `PERIGO`, `ALERTA`, `MEDIO`, `BAIXO`, `OK`) e mapeamento para **OWASP** e **CIS AWS Benchmark**.

**Buckets S3 (CIS 2.1)**
Public Access Block, bucket policy/ACL pública, criptografia, versionamento, log de acesso e política exigindo HTTPS.

**Permissões IAM e Roles (CIS 1)**
Conta root (MFA e access keys), política de senha, `AdministratorAccess` (gerenciada, inline com `Action:* Resource:*` ou herdada de grupo) e trust policies de roles que confiam em `*` ou em contas externas.

**Autenticação e Chaves (OWASP A07 / CIS 1)**
MFA, chaves com mais de 90 dias sem rotação, chaves nunca usadas, múltiplas chaves ativas e idade da senha de console (via credential report).

**Security Groups (CIS 5)**
Portas abertas para a internet em IPv4 **e** IPv6, destacando SSH/RDP/bancos como crítico.

**Logs CloudTrail (OWASP A09 / CIS 3)**
Configuração do trail (multi-região e validação de log) e eventos suspeitos das últimas 24h, com filtro anti-ruído (horário suspeito só para eventos de escrita).

**EC2**
IMDSv2 obrigatório (anti-SSRF), IP público, volumes EBS sem criptografia e monitoramento.

**RDS (CIS 2.3)** — acesso público, criptografia, backup, deletion protection e snapshots públicos.
**Snapshots e AMIs** — snapshots EBS e AMIs expostos publicamente.
**Lambda** — runtime sem suporte, segredos em variáveis de ambiente e Function URL sem autenticação.
**KMS (CIS 3.8)** — rotação automática de chave.
**GuardDuty** — detecção de ameaças ativa.
**VPC Flow Logs (CIS 3.9)** — VPCs sem registro de tráfego.
**Segredos** — Secrets Manager sem rotação e parâmetros SSM sensíveis em texto puro.
**Mensageria** — tópicos SNS e filas SQS com política pública.
**Containers (ECR)** — repositórios sem scan de imagem ou com política pública.
**Balanceadores e CDN** — ELB/ALB com listener HTTP, CloudFront permitindo HTTP e certificados ACM expirando.
**Bancos** — Redshift público/sem criptografia e ElastiCache sem criptografia.
**Postura da Conta** — Security Hub, AWS Config, criptografia padrão de EBS e IAM Access Analyzer.
**Rede** — Elastic IPs alocados e não associados.

Ao final é calculado um **score de risco** ponderado e o relatório pode ser salvo em **TXT ou HTML**.

---

## Como funciona por baixo

O projeto é dividido em dois arquivos.

**audit.py - lógica de auditoria**

Contém todas as funções de verificação AWS rodando em paralelo com `ThreadPoolExecutor` e a função `gerar_relatorio_ia` que conecta no Ollama local:

```python
with ThreadPoolExecutor(max_workers=6) as executor:
    futures = {executor.submit(fn): nome for nome, fn in VERIFICACOES.items()}
```

```python
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)
```

**app.py - interface gráfica**

Gerencia as duas telas com CustomTkinter. A tela de login passa as credenciais pra tela de auditoria, que chama o `audit.py` numa thread separada pra não travar a interface durante a análise.

---

## Como rodar

**Pré-requisitos**

- Python 3.8+
- Conta AWS (Free Tier funciona)
- Ollama instalado em [ollama.com](https://ollama.com)

**Instala o modelo**

```bash
ollama pull mistral
```

**Instala as dependências**

```bash
pip install boto3 customtkinter python-dotenv openai
```

**Configuração**

Cria um arquivo `.env` na raiz do projeto:

```
AWS_KEY=sua_chave_aws_aqui
AWS_SECRET=sua_chave_secreta_aws_aqui
```

Nunca sobe o `.env` pro GitHub. O `.gitignore` já está configurado pra ignorar ele.

**Rodando**

Certifica que o Ollama está ativo:

```bash
ollama serve
```

Depois roda a interface:

```bash
python app.py
```

---

## Tecnologias

- **Python** - linguagem principal
- **boto3** - SDK oficial da AWS pra Python
- **CustomTkinter** - interface gráfica moderna
- **ThreadPoolExecutor** - análise paralela dos módulos
- **Ollama + Mistral** - IA local, gratuita e sem limite
- **python-dotenv** - gerenciamento seguro de credenciais

---

## Permissões necessárias

A chave usada na auditoria precisa apenas de **acesso de leitura**. O ideal é anexar a policy gerenciada `SecurityAudit` (ou `ReadOnlyAccess`). Sem alguma permissão específica, o módulo afetado é ignorado de forma segura (ou marcado como não auditável) — a auditoria não quebra.

## Proximas melhorias

- Exportar relatorio em PDF (HTML já disponível)
- Integracao com Slack pra alertas em tempo real
- Historico de auditorias anteriores pra comparar evolucao
- Escolha do modelo de IA via interface
- Supressão de falsos-positivos (whitelist de recursos conhecidos)

---

## Autor

Desenvolvido por Carlos como parte da jornada pra se tornar Security AI Engineer.

---

Use a vontade, filhote.
