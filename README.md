# SecAudit AI - v2

>  Versão anterior (v1, em terminal): [github.com/carlosbrennoo/SecAudit-AI](https://github.com/carlosbrennoo/SecAudit-AI)

Ferramenta de auditoria de segurança AWS com **interface gráfica** e relatório gerado por **IA local**. Você coloca suas chaves AWS, ele varre a conta inteira procurando problemas de segurança e te entrega um relatório explicado em português — tudo rodando na sua máquina, sem custo e sem enviar nada pra nuvem.

Esta é a evolução do [SecAudit AI v1](https://github.com/carlosbrennoo/SecAudit-AI): a lógica continua local e paralela, mas agora com tela de login, cards de progresso em tempo real, muito mais verificações e relatório exibido direto na janela.

---

## O que mudou da v1 pra v2

**Interface gráfica com CustomTkinter**
Na v1 tudo rodava no terminal. Na v2 tem tela de login, um card pra cada módulo que fica amarelo enquanto analisa e verde quando termina, barra de progresso e aba de relatório.

**Chaves digitadas na hora**
As credenciais AWS são digitadas direto na tela de login e apagadas da memória assim que a auditoria termina. Nada de chave salva em arquivo.

**Muito mais verificações**
Saiu de 6 para **19 módulos**, cobrindo a conta inteira em **todas as regiões**.

**Score de risco e export**
No fim você vê um score de risco e pode salvar o relatório em **TXT ou HTML**.

---

## O que ele verifica

A auditoria roda em **todas as regiões habilitadas** da conta e cobre 19 módulos, com severidade padronizada (`CRITICO`, `PERIGO`, `ALERTA`, `MEDIO`, `BAIXO`, `OK`) e mapeamento para **OWASP** e **CIS AWS Benchmark**.

**Buckets S3 (CIS 2.1)**
Public Access Block, bucket policy/ACL pública, criptografia, versionamento, log de acesso e política exigindo HTTPS.

**Permissões IAM e Roles (CIS 1)**
Conta root (MFA e access keys), política de senha, `AdministratorAccess` (gerenciada, inline com `Action:* Resource:*` ou herdada de grupo) e trust policies de roles que confiam em `*` ou em contas externas.

**Autenticação e Chaves (OWASP A07 / CIS 1)**
MFA, chaves com mais de 90 dias sem rotação, chaves nunca usadas, múltiplas chaves ativas e idade da senha de console.

**Security Groups (CIS 5)**
Portas abertas para a internet em IPv4 **e** IPv6, destacando SSH/RDP/bancos como crítico.

**Logs CloudTrail (OWASP A09 / CIS 3)**
Configuração do trail (multi-região e validação de log) e eventos suspeitos das últimas 24h, com filtro anti-ruído.

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

## Como rodar

### 1. Pré-requisitos

- Python 3.8 ou superior
- Conta AWS (Free Tier funciona)
- [Ollama](https://ollama.com) instalado (é ele que gera o relatório com IA, localmente)

### 2. Baixe o modelo de IA

```bash
ollama pull mistral
```

### 3. Instale as dependências

```bash
pip install boto3 customtkinter openai
```

### 4. Deixe o Ollama ativo

Em um terminal separado:

```bash
ollama serve
```

### 5. Abra o programa

```bash
python app.py
```

Vai abrir a tela de login. **Cole sua Access Key e sua Secret Access Key da AWS** e clique em *Iniciar Auditoria*. As chaves ficam só na memória durante a análise — não são salvas em lugar nenhum.

> Não precisa criar nenhum arquivo de configuração nem `.env`. As chaves são informadas direto na tela.

---

## Que permissões a chave AWS precisa?

Apenas **leitura**. O ideal é usar uma chave com a policy gerenciada `SecurityAudit` (ou `ReadOnlyAccess`). Se faltar alguma permissão específica, o módulo afetado é ignorado com segurança (ou marcado como "não auditável") — a auditoria não quebra e o resto continua normalmente.

A ferramenta **nunca altera nada** na sua conta: só lê configurações para apontar os riscos.

---

## Como funciona por baixo

O projeto tem dois arquivos:

**`audit.py` — lógica de auditoria**
Roda todas as verificações em paralelo com `ThreadPoolExecutor`, varre todas as regiões e monta os dados. A função `gerar_relatorio_ia` envia o resultado para o Ollama local, que escreve o relatório:

```python
client = OpenAI(
    base_url="http://localhost:11434/v1",
    api_key="ollama"
)
```

**`app.py` — interface gráfica**
Gerencia as telas com CustomTkinter. A tela de login passa as chaves para a tela de auditoria, que chama o `audit.py` em uma thread separada pra não travar a janela durante a análise.

---

## Tecnologias

- **Python** — linguagem principal
- **boto3** — SDK oficial da AWS
- **CustomTkinter** — interface gráfica moderna
- **ThreadPoolExecutor** — análise paralela dos módulos e das regiões
- **Ollama + Mistral** — IA local, gratuita e sem limite

---

## Próximas melhorias

- Exportar relatório em PDF (HTML já disponível)
- Integração com Slack para alertas em tempo real
- Histórico de auditorias anteriores para comparar a evolução
- Escolha do modelo de IA pela interface
- Supressão de falsos-positivos (whitelist de recursos conhecidos)

---

## Autor

Desenvolvido por Carlos como parte da jornada pra se tornar Security AI Engineer.

---

Use a vontade, filhote.
