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

**Buckets S3**
Checa se algum bucket está público na internet sem querer e se os arquivos estão criptografados.

**Permissões IAM**
Verifica se algum usuário tem acesso de administrador sem precisar. Menos permissão, menos risco.

**Security Groups**
Detecta portas perigosas abertas pra internet, como a porta 22 (SSH) e 3389 (RDP).

**Autenticação - OWASP A07**
Verifica se usuários estão sem MFA ativado e se alguma chave de acesso está ativa há mais de 90 dias sem rotação.

**Logs CloudTrail - OWASP A09**
Analisa eventos das últimas 24 horas e detecta criação ou deleção de usuários, acessos de IPs públicos suspeitos, tentativas de login falhadas, ações em horário suspeito e uso do usuário root.

**Monitoramento EC2**
Verifica se as instâncias estão com monitoramento ativado.

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

## Proximas melhorias

- Suporte a multiplas regioes AWS
- Exportar relatorio em PDF
- Integracao com Slack pra alertas em tempo real
- Historico de auditorias anteriores pra comparar evolucao
- Escolha do modelo de IA via interface

---

## Autor

Desenvolvido por Carlos como parte da jornada pra se tornar Security AI Engineer.

---

Use a vontade, filhote.
