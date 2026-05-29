import io
import csv
import json
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from openai import OpenAI


# ──────────────────────────────────────────────
# Lista de módulos (usada também pela interface)
# ──────────────────────────────────────────────

MODULOS = [
    "S3", "IAM", "Chaves", "Security Groups", "CloudTrail", "EC2",
    "RDS", "Snapshots", "Lambda", "KMS", "GuardDuty", "VPC Flow Logs",
    "Segredos", "Mensageria", "Containers", "Balanceadores/CDN",
    "Bancos", "Postura da Conta", "Rede",
]

# Configuração de retry/backoff para lidar com throttling da AWS
_BOTO_CFG = Config(retries={'max_attempts': 6, 'mode': 'adaptive'})

# Portas extremamente sensíveis — abertas para o mundo viram [CRITICO]
PORTAS_CRITICAS = {
    22:    "SSH",
    3389:  "RDP",
    23:    "Telnet",
    21:    "FTP",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    1433:  "MSSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    5984:  "CouchDB",
    11211: "Memcached",
}

# Prefixos de eventos CloudTrail somente-leitura (não alteram nada) —
# usados para filtrar ruído na regra de "horário suspeito"
PREFIXOS_LEITURA = (
    "List", "Get", "Describe", "Lookup", "Search", "View",
    "BatchGet", "Head", "Select", "Generate", "Estimate", "Preview",
)

# Runtimes Lambda já descontinuados / sem suporte de segurança
RUNTIMES_EOL = {
    "python2.7", "python3.6", "python3.7",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10",
    "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1",
    "ruby2.5", "ruby2.7", "go1.x",
}

# Pesos para o score de risco (quanto maior, pior)
PESOS = {"criticos": 10, "perigos": 5, "alertas": 3, "medios": 2, "baixos": 1}


def _eh_somente_leitura(nome_evento: str) -> bool:
    return nome_evento.startswith(PREFIXOS_LEITURA)


def _negado(e) -> bool:
    """True se o erro for de permissão/autorização (não é insegurança, é falta de acesso)."""
    if isinstance(e, ClientError):
        return e.response.get('Error', {}).get('Code') in (
            'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
            'AuthFailure', 'NotAuthorized', 'Forbidden', 'OptInRequired',
        )
    return False


def _statements(doc):
    """Normaliza Statement de uma policy (str/dict/list) numa lista de dicts."""
    if isinstance(doc, str):
        try:
            doc = json.loads(urllib.parse.unquote(doc))
        except Exception:
            return []
    stmts = doc.get('Statement', []) if isinstance(doc, dict) else []
    if isinstance(stmts, dict):
        stmts = [stmts]
    return stmts


def _policy_publica(doc) -> bool:
    """True se algum statement Allow tem Principal '*' / {'AWS':'*'} sem Condition."""
    for s in _statements(doc):
        if s.get('Effect') != 'Allow':
            continue
        principal = s.get('Principal')
        publico = principal == '*' or (
            isinstance(principal, dict) and (
                principal.get('AWS') == '*'
                or (isinstance(principal.get('AWS'), list) and '*' in principal['AWS'])
            )
        )
        if publico and not s.get('Condition'):
            return True
    return False


def rodar_auditoria(aws_key: str, aws_secret: str, callback=None):
    """
    Executa todas as verificações de segurança AWS em paralelo, em todas as
    regiões habilitadas para os serviços regionais.

    Retorna:
        (secoes: dict, dados_finais: str, contagens: dict)
    """

    session = boto3.Session(
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name='us-east-1'
    )

    def _cb(nome, status):
        if callback:
            callback(nome, status)

    def _client(servico, regiao=None):
        return session.client(servico, region_name=regiao or 'us-east-1', config=_BOTO_CFG)

    # Conta atual (para detectar principals de contas externas em trust policies)
    try:
        conta_id = _client('sts').get_caller_identity()['Account']
    except Exception:
        conta_id = None

    def _listar_regioes():
        try:
            resp = _client('ec2').describe_regions(AllRegions=False)
            return sorted(r['RegionName'] for r in resp['Regions'])
        except Exception:
            return ['us-east-1']

    regioes = _listar_regioes()

    def _por_regiao(fn_regiao, paralelo=True):
        """Roda fn_regiao(regiao) em cada região, ignorando regiões inacessíveis."""
        resultados = []
        if paralelo:
            with ThreadPoolExecutor(max_workers=min(8, len(regioes))) as ex:
                futs = {ex.submit(fn_regiao, r): r for r in regioes}
                for f in as_completed(futs):
                    try:
                        resultados.extend(f.result())
                    except Exception:
                        continue
        else:
            for regiao in regioes:
                try:
                    resultados.extend(fn_regiao(regiao))
                except Exception:
                    continue
        return resultados

    # ──────────────────────────────────────────────
    # S3 (global) — CIS 2.1
    # ──────────────────────────────────────────────

    def verificar_s3():
        resultados = []
        s3 = _client('s3')
        _cb("S3", "iniciando")
        try:
            for bucket in s3.list_buckets()['Buckets']:
                nome = bucket['Name']
                try:
                    # Public Access Block — distinguindo "sem bloqueio" de "sem permissão"
                    publico = False
                    try:
                        block = s3.get_public_access_block(Bucket=nome)['PublicAccessBlockConfiguration']
                        publico = not all([
                            block.get('BlockPublicAcls', False),
                            block.get('IgnorePublicAcls', False),
                            block.get('BlockPublicPolicy', False),
                            block.get('RestrictPublicBuckets', False),
                        ])
                    except ClientError as e:
                        code = e.response['Error']['Code']
                        if code == 'NoSuchPublicAccessBlockConfiguration':
                            publico = True
                        elif _negado(e):
                            publico = None
                        else:
                            publico = True

                    if publico is None:
                        resultados.append(f"[INFO] {nome}: Public Access Block não auditável (sem permissão)")
                    elif publico:
                        resultados.append(f"[CRITICO] {nome} sem Public Access Block completo (pode ficar PÚBLICO)")
                    else:
                        resultados.append(f"[OK] {nome} com Public Access Block ativo")

                    # Policy pública
                    try:
                        if s3.get_bucket_policy_status(Bucket=nome)['PolicyStatus'].get('IsPublic'):
                            resultados.append(f"[CRITICO] {nome} tem bucket policy PÚBLICA")
                    except Exception:
                        pass

                    # ACL pública
                    try:
                        for grant in s3.get_bucket_acl(Bucket=nome).get('Grants', []):
                            uri = grant.get('Grantee', {}).get('URI', '')
                            if uri.endswith('AllUsers') or uri.endswith('AuthenticatedUsers'):
                                resultados.append(f"[CRITICO] {nome} tem ACL pública ({grant['Permission']})")
                                break
                    except Exception:
                        pass

                    # Criptografia
                    try:
                        s3.get_bucket_encryption(Bucket=nome)
                        resultados.append(f"[OK] {nome} com criptografia ativada")
                    except ClientError as e:
                        if _negado(e):
                            resultados.append(f"[INFO] {nome}: criptografia não auditável (sem permissão)")
                        else:
                            resultados.append(f"[MEDIO] {nome} sem criptografia ativada")

                    # Versionamento
                    try:
                        if s3.get_bucket_versioning(Bucket=nome).get('Status') != 'Enabled':
                            resultados.append(f"[BAIXO] {nome} sem versionamento (sem proteção contra deleção/ransomware)")
                    except Exception:
                        pass

                    # Logging de acesso
                    try:
                        if 'LoggingEnabled' not in s3.get_bucket_logging(Bucket=nome):
                            resultados.append(f"[BAIXO] {nome} sem log de acesso ativado")
                    except Exception:
                        pass

                    # HTTPS obrigatório
                    try:
                        pol = s3.get_bucket_policy(Bucket=nome)
                        if 'SecureTransport' not in pol.get('Policy', ''):
                            resultados.append(f"[BAIXO] {nome} sem política exigindo HTTPS (aws:SecureTransport)")
                    except ClientError as e:
                        if not _negado(e):
                            resultados.append(f"[BAIXO] {nome} sem política exigindo HTTPS (aws:SecureTransport)")

                except Exception as e:
                    resultados.append(f"[ERRO] {nome}: {e}")
            if not resultados:
                resultados.append("[OK] Nenhum bucket encontrado")
        except Exception as e:
            resultados.append(f"[ERRO] Falha ao listar buckets: {e}")
        _cb("S3", "concluido")
        return "Buckets S3 (CIS 2.1)", resultados

    # ──────────────────────────────────────────────
    # IAM (global) — root, password policy, usuários e roles
    # ──────────────────────────────────────────────

    def verificar_iam():
        resultados = []
        iam = _client('iam')
        _cb("IAM", "iniciando")
        try:
            # --- Conta root (CIS 1.x) ---
            try:
                resumo = iam.get_account_summary()['SummaryMap']
                if resumo.get('AccountMFAEnabled', 0) == 0:
                    resultados.append("[CRITICO] Conta ROOT sem MFA ativado")
                else:
                    resultados.append("[OK] Conta ROOT com MFA ativado")
                if resumo.get('AccountAccessKeysPresent', 0) > 0:
                    resultados.append("[CRITICO] Conta ROOT possui access keys ativas (remova imediatamente)")
            except Exception as e:
                resultados.append(f"[ERRO] Resumo da conta: {e}")

            # --- Password policy (CIS 1.8/1.9) ---
            try:
                pp = iam.get_account_password_policy()['PasswordPolicy']
                if pp.get('MinimumPasswordLength', 0) < 14:
                    resultados.append(
                        f"[MEDIO] Política de senha fraca (mínimo {pp.get('MinimumPasswordLength', 0)} caracteres; recomendado ≥14)"
                    )
                if not pp.get('ExpirePasswords'):
                    resultados.append("[BAIXO] Senhas sem expiração configurada")
            except ClientError as e:
                if _negado(e):
                    resultados.append("[INFO] Política de senha não auditável (sem permissão)")
                else:
                    resultados.append("[PERIGO] Conta sem política de senha definida")

            # --- Usuários ---
            for page in iam.get_paginator('list_users').paginate():
                for usuario in page['Users']:
                    nome = usuario['UserName']
                    try:
                        for policy in iam.list_attached_user_policies(UserName=nome)['AttachedPolicies']:
                            if policy['PolicyName'] == 'AdministratorAccess':
                                resultados.append(f"[PERIGO] {nome} tem AdministratorAccess (gerenciada)")
                    except Exception:
                        pass
                    try:
                        for pol_nome in iam.list_user_policies(UserName=nome)['PolicyNames']:
                            doc = iam.get_user_policy(UserName=nome, PolicyName=pol_nome)['PolicyDocument']
                            for s in _statements(doc):
                                if s.get('Effect') == 'Allow':
                                    acts = s.get('Action', [])
                                    acts = [acts] if isinstance(acts, str) else acts
                                    res = s.get('Resource', [])
                                    res = [res] if isinstance(res, str) else res
                                    if '*' in acts and '*' in res:
                                        resultados.append(f"[PERIGO] {nome} tem policy inline '{pol_nome}' com Action:* Resource:* (admin disfarçado)")
                                        break
                    except Exception:
                        pass
                    try:
                        for grupo in iam.list_groups_for_user(UserName=nome)['Groups']:
                            g_nome = grupo['GroupName']
                            for gp in iam.list_attached_group_policies(GroupName=g_nome)['AttachedPolicies']:
                                if gp['PolicyName'] == 'AdministratorAccess':
                                    resultados.append(f"[PERIGO] {nome} herda AdministratorAccess do grupo '{g_nome}'")
                    except Exception:
                        pass

            # --- Roles e trust policies ---
            for page in iam.get_paginator('list_roles').paginate():
                for role in page['Roles']:
                    rn = role['RoleName']
                    if rn.startswith('AWSServiceRoleFor'):
                        continue
                    for s in _statements(role.get('AssumeRolePolicyDocument', {})):
                        if s.get('Effect') != 'Allow':
                            continue
                        principal = s.get('Principal', {})
                        arns = []
                        if principal == '*':
                            arns = ['*']
                        elif isinstance(principal, dict):
                            p = principal.get('AWS')
                            if isinstance(p, str):
                                arns = [p]
                            elif isinstance(p, list):
                                arns = p
                        for arn in arns:
                            if arn == '*':
                                if s.get('Condition'):
                                    resultados.append(f"[MEDIO] Role '{rn}' pode ser assumida por qualquer um (Principal:* com Condition)")
                                else:
                                    resultados.append(f"[CRITICO] Role '{rn}' pode ser assumida por QUALQUER UM (Principal:* sem Condition)")
                            elif conta_id and 'arn:aws:iam' in arn and conta_id not in arn:
                                resultados.append(f"[MEDIO] Role '{rn}' confia em conta externa ({arn})")

            if not any(t in r for r in resultados for t in ('[CRITICO]', '[PERIGO]', '[MEDIO]')):
                resultados.append("[OK] Nenhuma permissão excessiva detectada em usuários e roles")
        except Exception as e:
            resultados.append(f"[ERRO] {e}")
        _cb("IAM", "concluido")
        return "Permissões IAM e Roles (CIS 1)", resultados

    # ──────────────────────────────────────────────
    # Chaves / MFA (global) — OWASP A07 / CIS 1
    # ──────────────────────────────────────────────

    def verificar_chaves():
        resultados = []
        iam = _client('iam')
        _cb("Chaves", "iniciando")
        try:
            agora = datetime.now(timezone.utc)
            encontrou = False
            for page in iam.get_paginator('list_users').paginate():
                for usuario in page['Users']:
                    nome = usuario['UserName']
                    if not iam.list_mfa_devices(UserName=nome)['MFADevices']:
                        resultados.append(f"[PERIGO] {nome} sem MFA ativado")
                        encontrou = True
                    ativas = [c for c in iam.list_access_keys(UserName=nome)['AccessKeyMetadata'] if c['Status'] == 'Active']
                    if len(ativas) > 1:
                        resultados.append(f"[MEDIO] {nome} tem {len(ativas)} chaves ativas simultâneas")
                        encontrou = True
                    for chave in ativas:
                        idade = (agora - chave['CreateDate']).days
                        if idade > 90:
                            resultados.append(f"[PERIGO] {nome} tem chave ativa com {idade} dias sem rotação")
                            encontrou = True
                        try:
                            uso = iam.get_access_key_last_used(AccessKeyId=chave['AccessKeyId'])
                            ultimo = uso['AccessKeyLastUsed'].get('LastUsedDate')
                            if ultimo is None:
                                resultados.append(f"[MEDIO] {nome} tem chave ativa NUNCA utilizada (remova)")
                                encontrou = True
                            elif (agora - ultimo).days > 90:
                                resultados.append(f"[BAIXO] {nome} tem chave ativa sem uso há {(agora - ultimo).days} dias")
                                encontrou = True
                        except Exception:
                            pass

            # Credential report — idade da senha de console
            try:
                conteudo = None
                for _ in range(4):
                    try:
                        conteudo = iam.get_credential_report()['Content'].decode('utf-8')
                        break
                    except ClientError as e:
                        if e.response['Error']['Code'] in ('ReportNotPresent', 'ReportInProgress', 'ReportExpired'):
                            iam.generate_credential_report()
                            time.sleep(2)
                        else:
                            raise
                if conteudo:
                    for linha in csv.DictReader(io.StringIO(conteudo)):
                        if linha.get('password_enabled') != 'true':
                            continue
                        troca = linha.get('password_last_changed', 'N/A')
                        if troca not in ('N/A', 'no_information', ''):
                            try:
                                dt = datetime.fromisoformat(troca.replace('Z', '+00:00'))
                                if (agora - dt).days > 90:
                                    resultados.append(f"[BAIXO] {linha['user']} com senha de console sem troca há {(agora - dt).days} dias")
                                    encontrou = True
                            except Exception:
                                pass
            except Exception:
                pass

            if not encontrou:
                resultados.append("[OK] Nenhuma chave/senha com problemas")
        except Exception as e:
            resultados.append(f"[ERRO] {e}")
        _cb("Chaves", "concluido")
        return "Autenticação e Chaves (OWASP A07 / CIS 1)", resultados

    # ──────────────────────────────────────────────
    # Security Groups (multi-região) — CIS 5
    # ──────────────────────────────────────────────

    def verificar_security_groups():
        _cb("Security Groups", "iniciando")

        def _na_regiao(regiao):
            achados = []
            ec2 = _client('ec2', regiao)
            for grupo in ec2.describe_security_groups()['SecurityGroups']:
                nome = grupo['GroupName']
                for regra in grupo['IpPermissions']:
                    aberto = (
                        any(ip.get('CidrIp') == '0.0.0.0/0' for ip in regra.get('IpRanges', []))
                        or any(ip.get('CidrIpv6') == '::/0' for ip in regra.get('Ipv6Ranges', []))
                    )
                    if not aberto:
                        continue
                    proto = regra.get('IpProtocol')
                    de, ate = regra.get('FromPort'), regra.get('ToPort')
                    if proto == '-1' or de is None:
                        achados.append(f"[CRITICO] [{regiao}] SG '{nome}' libera TODO o tráfego para a internet")
                        continue
                    criticas = [f"{p}/{svc}" for p, svc in PORTAS_CRITICAS.items() if de <= p <= ate]
                    faixa = str(de) if de == ate else f"{de}-{ate}"
                    if criticas:
                        achados.append(f"[CRITICO] [{regiao}] SG '{nome}' expõe {', '.join(criticas)} (porta {faixa}) para a internet")
                    else:
                        achados.append(f"[PERIGO] [{regiao}] SG '{nome}' com porta {faixa} aberta para a internet")
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhuma porta perigosa aberta em nenhuma região")
        _cb("Security Groups", "concluido")
        return "Security Groups (CIS 5)", resultados

    # ──────────────────────────────────────────────
    # CloudTrail (eventos + config) — OWASP A09 / CIS 3
    # ──────────────────────────────────────────────

    def verificar_cloudtrail():
        resultados = []
        _cb("CloudTrail", "iniciando")
        try:
            ct = _client('cloudtrail')
            trails = ct.describe_trails(includeShadowTrails=False).get('trailList', [])
            if not trails:
                resultados.append("[PERIGO] Nenhum trail do CloudTrail configurado (sem auditoria de API)")
            else:
                if not any(t.get('IsMultiRegionTrail') for t in trails):
                    resultados.append("[MEDIO] Nenhum trail multi-região (eventos de outras regiões não são registrados)")
                if not any(t.get('LogFileValidationEnabled') for t in trails):
                    resultados.append("[BAIXO] Validação de integridade de log desativada em todos os trails")
        except Exception as e:
            resultados.append(f"[ERRO] Config do CloudTrail: {e}")

        try:
            cloudtrail = _client('cloudtrail')
            inicio = datetime.now(timezone.utc) - timedelta(hours=24)
            registrados = set()
            encontrou = False
            EVENTOS_SUSPEITOS = {
                'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'DetachUserPolicy',
                'PutUserPolicy', 'CreateAccessKey', 'DeleteTrail', 'StopLogging',
            }
            for pagina in cloudtrail.get_paginator('lookup_events').paginate(StartTime=inicio):
                for evento in pagina['Events']:
                    nome_evento = evento['EventName']
                    usuario = evento.get('Username', 'sistema')
                    horario = evento['EventTime']
                    hora = horario.hour
                    ip = evento.get('SourceIPAddress', '')

                    if nome_evento in EVENTOS_SUSPEITOS:
                        chave = f"iam-{nome_evento}-{usuario}"
                        if chave not in registrados:
                            registrados.add(chave)
                            resultados.append(f"[ALERTA] Evento sensível: {nome_evento} executado por {usuario}")
                            encontrou = True

                    if ip and not any(ip.startswith(p) for p in ('192.168', '10.', '172.16')) and not ip.endswith('.amazonaws.com'):
                        chave = f"ip-{ip}-{nome_evento}"
                        if chave not in registrados:
                            registrados.add(chave)
                            resultados.append(f"[ALERTA] Acesso de IP público {ip} — evento: {nome_evento} por {usuario}")
                            encontrou = True

                    if nome_evento == 'ConsoleLogin':
                        if '"errorMessage": "Failed authentication"' in evento.get('CloudTrailEvent', ''):
                            chave = f"login-{usuario}"
                            if chave not in registrados:
                                registrados.add(chave)
                                resultados.append(f"[ALERTA] Tentativa de login falhada por {usuario}")
                                encontrou = True

                    if usuario == 'root':
                        chave = f"root-{nome_evento}"
                        if chave not in registrados:
                            registrados.add(chave)
                            msg = (f"[ALERTA] {nome_evento} pelo root em horário suspeito ({horario})"
                                   if 0 <= hora <= 6 else f"[ALERTA] {nome_evento} executado pelo usuário root")
                            resultados.append(msg)
                            encontrou = True
                    elif (0 <= hora <= 6) and not _eh_somente_leitura(nome_evento):
                        chave = f"suspeito-{nome_evento}-{usuario}"
                        if chave not in registrados:
                            registrados.add(chave)
                            resultados.append(f"[ALERTA] {nome_evento} (escrita) por {usuario} em horário suspeito ({horario})")
                            encontrou = True

            if not encontrou:
                resultados.append("[OK] Nenhum evento suspeito nas últimas 24 horas")
        except Exception as e:
            resultados.append(f"[ERRO] {e}")
        _cb("CloudTrail", "concluido")
        return "Logs CloudTrail — últimas 24h (OWASP A09 / CIS 3)", resultados

    # ──────────────────────────────────────────────
    # EC2 (multi-região) — IMDSv2, IP público, EBS, monitoramento
    # ──────────────────────────────────────────────

    def verificar_ec2():
        _cb("EC2", "iniciando")

        def _na_regiao(regiao):
            achados = []
            ec2 = _client('ec2', regiao)
            for page in ec2.get_paginator('describe_instances').paginate():
                for reserva in page['Reservations']:
                    for inst in reserva['Instances']:
                        if inst.get('State', {}).get('Name') == 'terminated':
                            continue
                        inst_id = inst['InstanceId']
                        nome = next((t['Value'] for t in inst.get('Tags', []) if t['Key'] == 'Name'), inst_id)
                        if inst.get('MetadataOptions', {}).get('HttpTokens') != 'required':
                            achados.append(f"[PERIGO] [{regiao}] '{nome}' sem IMDSv2 obrigatório (risco de SSRF/roubo de credenciais)")
                        if inst.get('PublicIpAddress'):
                            achados.append(f"[MEDIO] [{regiao}] '{nome}' com IP público ({inst['PublicIpAddress']})")
                        if inst.get('Monitoring', {}).get('State') != 'enabled':
                            achados.append(f"[BAIXO] [{regiao}] '{nome}' com monitoramento detalhado desativado")
            for page in ec2.get_paginator('describe_volumes').paginate():
                for vol in page['Volumes']:
                    if not vol.get('Encrypted'):
                        achados.append(f"[MEDIO] [{regiao}] Volume EBS {vol['VolumeId']} sem criptografia")
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum problema encontrado nas instâncias/volumes EC2")
        _cb("EC2", "concluido")
        return "EC2 — IMDSv2, IP público e EBS", resultados

    # ──────────────────────────────────────────────
    # RDS (multi-região) — CIS 2.3 + snapshots públicos
    # ──────────────────────────────────────────────

    def verificar_rds():
        _cb("RDS", "iniciando")

        def _na_regiao(regiao):
            achados = []
            rds = _client('rds', regiao)
            for page in rds.get_paginator('describe_db_instances').paginate():
                for db in page['DBInstances']:
                    ident = db['DBInstanceIdentifier']
                    if db.get('PubliclyAccessible'):
                        achados.append(f"[CRITICO] [{regiao}] Banco RDS '{ident}' acessível publicamente")
                    if not db.get('StorageEncrypted'):
                        achados.append(f"[PERIGO] [{regiao}] Banco RDS '{ident}' sem criptografia em repouso")
                    if db.get('BackupRetentionPeriod', 0) == 0:
                        achados.append(f"[MEDIO] [{regiao}] Banco RDS '{ident}' sem backup automático")
                    if not db.get('DeletionProtection'):
                        achados.append(f"[BAIXO] [{regiao}] Banco RDS '{ident}' sem proteção contra deleção")
            # Snapshots manuais públicos
            try:
                for snap in rds.describe_db_snapshots(SnapshotType='manual').get('DBSnapshots', []):
                    sid = snap['DBSnapshotIdentifier']
                    attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=sid)
                    for a in attrs['DBSnapshotAttributesResult']['DBSnapshotAttributes']:
                        if a['AttributeName'] == 'restore' and 'all' in a.get('AttributeValues', []):
                            achados.append(f"[CRITICO] [{regiao}] Snapshot RDS '{sid}' está PÚBLICO (dados expostos)")
            except Exception:
                pass
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum banco/snapshot RDS com problemas")
        _cb("RDS", "concluido")
        return "Bancos RDS (CIS 2.3)", resultados

    # ──────────────────────────────────────────────
    # Snapshots e AMIs públicos (multi-região)
    # ──────────────────────────────────────────────

    def verificar_snapshots():
        _cb("Snapshots", "iniciando")

        def _na_regiao(regiao):
            achados = []
            ec2 = _client('ec2', regiao)
            for snap in ec2.describe_snapshots(OwnerIds=['self'], RestorableByUserIds=['all']).get('Snapshots', []):
                achados.append(f"[CRITICO] [{regiao}] Snapshot EBS {snap['SnapshotId']} está PÚBLICO (dados expostos)")
            for img in ec2.describe_images(Owners=['self']).get('Images', []):
                if img.get('Public'):
                    achados.append(f"[CRITICO] [{regiao}] AMI {img['ImageId']} ({img.get('Name', '')}) está PÚBLICA")
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum snapshot ou AMI público encontrado")
        _cb("Snapshots", "concluido")
        return "Snapshots e AMIs públicos", resultados

    # ──────────────────────────────────────────────
    # Lambda (multi-região)
    # ──────────────────────────────────────────────

    def verificar_lambda():
        _cb("Lambda", "iniciando")

        def _na_regiao(regiao):
            achados = []
            lam = _client('lambda', regiao)
            for page in lam.get_paginator('list_functions').paginate():
                for fn in page['Functions']:
                    nome = fn['FunctionName']
                    if fn.get('Runtime', '') in RUNTIMES_EOL:
                        achados.append(f"[PERIGO] [{regiao}] Função '{nome}' usa runtime sem suporte ({fn['Runtime']})")
                    env = fn.get('Environment', {}).get('Variables', {})
                    suspeitas = [k for k in env if any(t in k.upper() for t in ('SECRET', 'PASSWORD', 'TOKEN', 'KEY', 'PASS', 'CREDENTIAL'))]
                    if suspeitas:
                        achados.append(f"[MEDIO] [{regiao}] Função '{nome}' com possíveis segredos em env vars: {', '.join(suspeitas)}")
                    try:
                        if lam.get_function_url_config(FunctionName=nome).get('AuthType') == 'NONE':
                            achados.append(f"[PERIGO] [{regiao}] Função '{nome}' com Function URL pública SEM autenticação")
                    except Exception:
                        pass
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhuma função Lambda com problemas")
        _cb("Lambda", "concluido")
        return "Funções Lambda", resultados

    # ──────────────────────────────────────────────
    # KMS (multi-região) — CIS 3.8
    # ──────────────────────────────────────────────

    def verificar_kms():
        _cb("KMS", "iniciando")

        def _na_regiao(regiao):
            achados = []
            kms = _client('kms', regiao)
            for page in kms.get_paginator('list_keys').paginate():
                for k in page['Keys']:
                    key_id = k['KeyId']
                    try:
                        meta = kms.describe_key(KeyId=key_id)['KeyMetadata']
                        if meta.get('KeyManager') != 'CUSTOMER' or meta.get('KeyState') != 'Enabled':
                            continue
                        if not kms.get_key_rotation_status(KeyId=key_id).get('KeyRotationEnabled'):
                            achados.append(f"[MEDIO] [{regiao}] Chave KMS {key_id} sem rotação automática")
                    except Exception:
                        continue
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Chaves KMS do cliente com rotação ativa")
        _cb("KMS", "concluido")
        return "Chaves KMS (CIS 3.8)", resultados

    # ──────────────────────────────────────────────
    # GuardDuty (multi-região)
    # ──────────────────────────────────────────────

    def verificar_guardduty():
        _cb("GuardDuty", "iniciando")

        def _na_regiao(regiao):
            gd = _client('guardduty', regiao)
            if not gd.list_detectors().get('DetectorIds', []):
                return [f"[MEDIO] [{regiao}] GuardDuty desativado (sem detecção de ameaças)"]
            return []

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] GuardDuty ativo nas regiões verificadas")
        _cb("GuardDuty", "concluido")
        return "GuardDuty — detecção de ameaças", resultados

    # ──────────────────────────────────────────────
    # VPC Flow Logs (multi-região) — CIS 3.9
    # ──────────────────────────────────────────────

    def verificar_flow_logs():
        _cb("VPC Flow Logs", "iniciando")

        def _na_regiao(regiao):
            achados = []
            ec2 = _client('ec2', regiao)
            vpcs = ec2.describe_vpcs().get('Vpcs', [])
            if not vpcs:
                return achados
            com_log = {f.get('ResourceId') for f in ec2.describe_flow_logs().get('FlowLogs', [])}
            for vpc in vpcs:
                if vpc['VpcId'] not in com_log:
                    achados.append(f"[MEDIO] [{regiao}] VPC {vpc['VpcId']} sem Flow Logs (tráfego não registrado)")
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Todas as VPCs com Flow Logs ativos")
        _cb("VPC Flow Logs", "concluido")
        return "VPC Flow Logs (CIS 3.9)", resultados

    # ──────────────────────────────────────────────
    # Segredos (multi-região) — Secrets Manager + SSM
    # ──────────────────────────────────────────────

    def verificar_segredos():
        _cb("Segredos", "iniciando")

        def _na_regiao(regiao):
            achados = []
            sm = _client('secretsmanager', regiao)
            for page in sm.get_paginator('list_secrets').paginate():
                for seg in page.get('SecretList', []):
                    if not seg.get('RotationEnabled'):
                        achados.append(f"[MEDIO] [{regiao}] Secret '{seg['Name']}' sem rotação automática")
            ssm = _client('ssm', regiao)
            for page in ssm.get_paginator('describe_parameters').paginate():
                for p in page.get('Parameters', []):
                    nome = p['Name']
                    if p.get('Type') == 'String' and any(t in nome.lower() for t in ('secret', 'password', 'senha', 'token', 'key', 'cred')):
                        achados.append(f"[PERIGO] [{regiao}] Parâmetro SSM '{nome}' guarda dado sensível em texto puro (use SecureString)")
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum problema com segredos")
        _cb("Segredos", "concluido")
        return "Segredos (Secrets Manager / SSM)", resultados

    # ──────────────────────────────────────────────
    # Mensageria (multi-região) — SNS + SQS públicos
    # ──────────────────────────────────────────────

    def verificar_mensageria():
        _cb("Mensageria", "iniciando")

        def _na_regiao(regiao):
            achados = []
            sns = _client('sns', regiao)
            for page in sns.get_paginator('list_topics').paginate():
                for topic in page.get('Topics', []):
                    arn = topic['TopicArn']
                    try:
                        pol = sns.get_topic_attributes(TopicArn=arn)['Attributes'].get('Policy')
                        if pol and _policy_publica(json.loads(pol)):
                            achados.append(f"[PERIGO] [{regiao}] Tópico SNS '{arn.split(':')[-1]}' tem política PÚBLICA")
                    except Exception:
                        pass
            sqs = _client('sqs', regiao)
            try:
                for url in sqs.list_queues().get('QueueUrls', []):
                    try:
                        pol = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['Policy'])['Attributes'].get('Policy')
                        if pol and _policy_publica(json.loads(pol)):
                            achados.append(f"[PERIGO] [{regiao}] Fila SQS '{url.split('/')[-1]}' tem política PÚBLICA")
                    except Exception:
                        pass
            except Exception:
                pass
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum tópico/fila público")
        _cb("Mensageria", "concluido")
        return "Mensageria (SNS / SQS)", resultados

    # ──────────────────────────────────────────────
    # Containers (multi-região) — ECR
    # ──────────────────────────────────────────────

    def verificar_containers():
        _cb("Containers", "iniciando")

        def _na_regiao(regiao):
            achados = []
            ecr = _client('ecr', regiao)
            for page in ecr.get_paginator('describe_repositories').paginate():
                for repo in page.get('repositories', []):
                    nome = repo['repositoryName']
                    if not repo.get('imageScanningConfiguration', {}).get('scanOnPush'):
                        achados.append(f"[BAIXO] [{regiao}] Repositório ECR '{nome}' sem scan de imagem no push")
                    try:
                        pol = ecr.get_repository_policy(repositoryName=nome).get('policyText')
                        if pol and _policy_publica(json.loads(pol)):
                            achados.append(f"[PERIGO] [{regiao}] Repositório ECR '{nome}' com política PÚBLICA")
                    except Exception:
                        pass
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum problema nos repositórios de container")
        _cb("Containers", "concluido")
        return "Containers (ECR)", resultados

    # ──────────────────────────────────────────────
    # Balanceadores e CDN — ELB/ALB + ACM (regional) + CloudFront (global)
    # ──────────────────────────────────────────────

    def verificar_balanceadores():
        _cb("Balanceadores/CDN", "iniciando")

        def _na_regiao(regiao):
            achados = []
            # ALB/NLB
            try:
                elbv2 = _client('elbv2', regiao)
                for lb in elbv2.describe_load_balancers().get('LoadBalancers', []):
                    arn = lb['LoadBalancerArn']
                    for lst in elbv2.describe_listeners(LoadBalancerArn=arn).get('Listeners', []):
                        if lst.get('Protocol') == 'HTTP':
                            achados.append(f"[MEDIO] [{regiao}] Load balancer '{lb['LoadBalancerName']}' com listener HTTP (sem TLS)")
            except Exception:
                pass
            # Classic ELB
            try:
                elb = _client('elb', regiao)
                for lb in elb.describe_load_balancers().get('LoadBalancerDescriptions', []):
                    for ld in lb.get('ListenerDescriptions', []):
                        if ld['Listener'].get('Protocol') in ('HTTP', 'TCP'):
                            achados.append(f"[MEDIO] [{regiao}] ELB clássico '{lb['LoadBalancerName']}' com listener {ld['Listener']['Protocol']} (sem TLS)")
                            break
            except Exception:
                pass
            # ACM — certificados expirando
            try:
                acm = _client('acm', regiao)
                for cert in acm.list_certificates().get('CertificateSummaryList', []):
                    d = acm.describe_certificate(CertificateArn=cert['CertificateArn'])['Certificate']
                    fim = d.get('NotAfter')
                    if fim:
                        dias = (fim - datetime.now(timezone.utc)).days
                        if dias < 0:
                            achados.append(f"[PERIGO] [{regiao}] Certificado '{d.get('DomainName')}' EXPIRADO")
                        elif dias <= 30:
                            achados.append(f"[MEDIO] [{regiao}] Certificado '{d.get('DomainName')}' expira em {dias} dias")
            except Exception:
                pass
            return achados

        resultados = _por_regiao(_na_regiao)
        # CloudFront (global)
        try:
            cf = _client('cloudfront')
            for page in cf.get_paginator('list_distributions').paginate():
                for dist in page.get('DistributionList', {}).get('Items', []):
                    dcfg = dist.get('DefaultCacheBehavior', {})
                    if dcfg.get('ViewerProtocolPolicy') == 'allow-all':
                        resultados.append(f"[MEDIO] CloudFront '{dist['Id']}' permite HTTP (ViewerProtocolPolicy allow-all)")
        except Exception:
            pass

        if not resultados:
            resultados.append("[OK] Nenhum problema em balanceadores, CDN ou certificados")
        _cb("Balanceadores/CDN", "concluido")
        return "Balanceadores e CDN (ELB/ALB/CloudFront/ACM)", resultados

    # ──────────────────────────────────────────────
    # Bancos (multi-região) — Redshift + ElastiCache
    # ──────────────────────────────────────────────

    def verificar_bancos():
        _cb("Bancos", "iniciando")

        def _na_regiao(regiao):
            achados = []
            try:
                rs = _client('redshift', regiao)
                for c in rs.describe_clusters().get('Clusters', []):
                    cid = c['ClusterIdentifier']
                    if c.get('PubliclyAccessible'):
                        achados.append(f"[CRITICO] [{regiao}] Cluster Redshift '{cid}' acessível publicamente")
                    if not c.get('Encrypted'):
                        achados.append(f"[PERIGO] [{regiao}] Cluster Redshift '{cid}' sem criptografia")
            except Exception:
                pass
            try:
                ec = _client('elasticache', regiao)
                for rg in ec.describe_replication_groups().get('ReplicationGroups', []):
                    rid = rg['ReplicationGroupId']
                    if not rg.get('AtRestEncryptionEnabled'):
                        achados.append(f"[MEDIO] [{regiao}] ElastiCache '{rid}' sem criptografia em repouso")
                    if not rg.get('TransitEncryptionEnabled'):
                        achados.append(f"[BAIXO] [{regiao}] ElastiCache '{rid}' sem criptografia em trânsito")
            except Exception:
                pass
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum problema em Redshift/ElastiCache")
        _cb("Bancos", "concluido")
        return "Bancos (Redshift / ElastiCache)", resultados

    # ──────────────────────────────────────────────
    # Postura da Conta — Security Hub, Config, EBS default, Access Analyzer
    # ──────────────────────────────────────────────

    def verificar_postura():
        _cb("Postura da Conta", "iniciando")

        def _na_regiao(regiao):
            # Retorna marcadores (tipo, regiao) — agregados depois, pois são
            # controles de NÍVEL DE CONTA (repeti-los por região vira ruído)
            achados = []
            try:
                _client('securityhub', regiao).describe_hub()
            except ClientError as e:
                if e.response['Error']['Code'] in ('InvalidAccessException', 'ResourceNotFoundException'):
                    achados.append(('securityhub', regiao))
            except Exception:
                pass
            try:
                if not _client('config', regiao).describe_configuration_recorders().get('ConfigurationRecorders', []):
                    achados.append(('config', regiao))
            except Exception:
                pass
            try:
                if not _client('ec2', regiao).get_ebs_encryption_by_default().get('EbsEncryptionByDefault'):
                    achados.append(('ebs', regiao))
            except Exception:
                pass
            try:
                if not _client('accessanalyzer', regiao).list_analyzers().get('analyzers', []):
                    achados.append(('aa', regiao))
            except Exception:
                pass
            return achados

        brutos = _por_regiao(_na_regiao)
        grupos = {}
        for tipo, regiao in brutos:
            grupos.setdefault(tipo, []).append(regiao)

        total = len(regioes)
        rotulos = [
            ('securityhub', "[MEDIO]", "Security Hub desativado"),
            ('config',      "[MEDIO]", "AWS Config desativado (sem registro de configuração)"),
            ('ebs',         "[BAIXO]", "Criptografia padrão de EBS desativada"),
            ('aa',          "[BAIXO]", "IAM Access Analyzer desativado"),
        ]
        resultados = []
        for tipo, sev, desc in rotulos:
            regs = grupos.get(tipo)
            if regs:
                resultados.append(f"{sev} {desc} em {len(regs)}/{total} regiões")

        if not resultados:
            resultados.append("[OK] Postura de segurança da conta adequada")
        _cb("Postura da Conta", "concluido")
        return "Postura da Conta (Security Hub / Config / Access Analyzer)", resultados

    # ──────────────────────────────────────────────
    # Rede (multi-região) — Elastic IPs órfãos
    # ──────────────────────────────────────────────

    def verificar_rede():
        _cb("Rede", "iniciando")

        def _na_regiao(regiao):
            achados = []
            ec2 = _client('ec2', regiao)
            for addr in ec2.describe_addresses().get('Addresses', []):
                if not addr.get('AssociationId') and not addr.get('InstanceId'):
                    achados.append(f"[BAIXO] [{regiao}] Elastic IP {addr.get('PublicIp')} alocado mas não associado (custo e resíduo)")
            return achados

        resultados = _por_regiao(_na_regiao)
        if not resultados:
            resultados.append("[OK] Nenhum Elastic IP órfão")
        _cb("Rede", "concluido")
        return "Rede (Elastic IPs)", resultados

    # ──────────────────────────────────────────────
    # Execução paralela
    # ──────────────────────────────────────────────

    VERIFICACOES = {
        "S3":                verificar_s3,
        "IAM":               verificar_iam,
        "Chaves":            verificar_chaves,
        "Security Groups":   verificar_security_groups,
        "CloudTrail":        verificar_cloudtrail,
        "EC2":               verificar_ec2,
        "RDS":               verificar_rds,
        "Snapshots":         verificar_snapshots,
        "Lambda":            verificar_lambda,
        "KMS":               verificar_kms,
        "GuardDuty":         verificar_guardduty,
        "VPC Flow Logs":     verificar_flow_logs,
        "Segredos":          verificar_segredos,
        "Mensageria":        verificar_mensageria,
        "Containers":        verificar_containers,
        "Balanceadores/CDN": verificar_balanceadores,
        "Bancos":            verificar_bancos,
        "Postura da Conta":  verificar_postura,
        "Rede":              verificar_rede,
    }

    secoes = {}
    with ThreadPoolExecutor(max_workers=len(VERIFICACOES)) as executor:
        futures = {executor.submit(fn): nome for nome, fn in VERIFICACOES.items()}
        for future in as_completed(futures):
            try:
                secao, resultados = future.result()
                secoes[secao] = resultados
            except Exception as e:
                secoes[f"Erro-{futures[future]}"] = [f"[ERRO] {e}"]

    # ──────────────────────────────────────────────
    # Montar dados estruturados
    # ──────────────────────────────────────────────

    todas_as_linhas = []
    for secao, itens in secoes.items():
        todas_as_linhas.append(f"\n=== {secao} ===")
        for item in itens:
            todas_as_linhas.append(f"  {item}")
    dados_estruturados = "\n".join(todas_as_linhas)

    todos = [item for itens in secoes.values() for item in itens]
    contagens = {
        "criticos": sum('[CRITICO]' in r for r in todos),
        "perigos":  sum('[PERIGO]'  in r for r in todos),
        "alertas":  sum('[ALERTA]'  in r for r in todos),
        "medios":   sum('[MEDIO]'   in r for r in todos),
        "baixos":   sum('[BAIXO]'   in r for r in todos),
    }
    contagens["score"] = sum(contagens[k] * PESOS[k] for k in PESOS)

    resumo = (
        f"RESUMO GERAL ({len(regioes)} regiões verificadas):\n"
        f"- Score de risco : {contagens['score']}\n"
        f"- Críticos : {contagens['criticos']}\n"
        f"- Perigos  : {contagens['perigos']}\n"
        f"- Alertas  : {contagens['alertas']}\n"
        f"- Médios   : {contagens['medios']}\n"
        f"- Baixos   : {contagens['baixos']}\n"
    )

    dados_finais = resumo + dados_estruturados
    return secoes, dados_finais, contagens


def gerar_relatorio_ia(openai_key: str, dados_finais: str, modo: str = "detalhado") -> str:
    """Gera o relatório via Ollama local (Mistral). openai_key mantido por compatibilidade."""

    if modo == "resumido":
        instrucao = (
            "Você é um analista de segurança cloud brasileiro com 10 anos de experiência. "
            "Escreva APENAS em português do Brasil, com linguagem clara e profissional. "
            "Você recebeu resultados de uma auditoria AWS. "
            "Escreva um resumo executivo CURTO (máximo 300 palavras) com:\n"
            "1. Total de problemas por severidade\n"
            "2. Os 3 riscos mais críticos\n"
            "3. Ação imediata mais urgente\n\n"
            f"{dados_finais}"
        )
    else:
        instrucao = (
            "Você é um analista de segurança cloud brasileiro com 10 anos de experiência. "
            "Escreva APENAS em português do Brasil, com linguagem clara e profissional. "
            "Você recebeu os resultados de uma auditoria de segurança AWS organizados por seção. "
            "Escreva um relatório completo com as seguintes partes:\n"
            "1. Resumo executivo (visão geral dos problemas)\n"
            "2. Detalhamento por seção — explique cada problema encontrado e o risco associado\n"
            "3. Ações corretivas recomendadas — objetivas e ordenadas por prioridade\n"
            "Quando fizer sentido, relacione os achados aos controles do CIS AWS Benchmark e do OWASP.\n"
            "Não omita nenhum item. Use os prefixos [CRITICO], [PERIGO], [ALERTA], [MEDIO], [BAIXO] e [OK] "
            "para referenciar cada item.\n\n"
            f"{dados_finais}"
        )

    try:
        client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
        response = client.chat.completions.create(
            model="mistral",
            messages=[{"role": "user", "content": instrucao}],
            max_tokens=4096
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Erro ao conectar com Ollama: {e}\n\nVerifique se o Ollama está rodando com: ollama serve"
