import re
from typing import Set, List
from src.domain.models import Intent

class NileParser:
    @staticmethod
    def _validate_syntax(nile_script: str) -> None:
        """Verifica se há erros de sintaxe (aspas duplas, sem aspas, vazios ou ausentes)."""
        # 1. Verifica se 'from' e 'to' existem no script
        if not re.search(r"\bfrom\s+", nile_script):
            raise ValueError("Erro de sintaxe: a cláusula de origem ('from') é obrigatória.")
        if not re.search(r"\bto\s+", nile_script):
            raise ValueError("Erro de sintaxe: a cláusula de destino ('to') é obrigatória.")

        # 2. Garante que 'from' e 'to' usem group(...) ou endpoint(...)
        from_target = re.search(r"\bfrom\s+([^\s]+)", nile_script)
        if from_target and not re.match(r"^(?:group|endpoint)\(", from_target.group(1)):
            raise ValueError(
                f"Erro na origem: '{from_target.group(1)}'. A origem deve ser endpoint('...') ou group('...')."
            )

        to_target = re.search(r"\bto\s+([^\s]+)", nile_script)
        if to_target and not re.match(r"^(?:group|endpoint)\(", to_target.group(1)):
            raise ValueError(
                f"Erro no destino: '{to_target.group(1)}'. O destino deve ser endpoint('...') ou group('...')."
            )

        # 3. Encontra todas as chamadas de funções da regra
        terms = re.findall(r"\b(group|endpoint|middlebox|traffic|bandwidth|latency|packet_loss|priority)\s*\((.*?)\)", nile_script)
        
        for func_name, raw_arg in terms:
            arg = raw_arg.strip()

            # Cenário A: Vazio sem nada entre parênteses
            if not arg:
                raise ValueError(f"Erro em {func_name}(): o termo não pode estar vazio.")

            # Cenário B: Uso de aspas duplas
            if '"' in arg:
                raise ValueError(
                    f"Erro em {func_name}({raw_arg}): aspas duplas não são permitidas. "
                    f"Utilize apenas aspas simples: {func_name}('{arg.replace('\"', '')}')."
                )

            # Cenário C: Tem aspas simples
            if arg.startswith("'") and arg.endswith("'"):
                content = arg[1:-1].strip()
                if not content:
                    raise ValueError(f"Erro em {func_name}('{arg[1:-1]}'): o valor dentro das aspas não pode estar vazio.")
            else:
                # Cenário D: Não tem aspas simples
                raise ValueError(
                    f"Erro em {func_name}({raw_arg}): o termo está sem aspas. "
                    f"Utilize aspas simples: {func_name}('{arg}')."
                )

    @staticmethod
    def parse(nile_script: str) -> Intent:
        # 1. Faz a checagem rigorosa
        NileParser._validate_syntax(nile_script)

        # 2. Extrai origem e destino (garantidos pela validação)
        src_match = re.search(r"from\s+(group|endpoint)\('([^']+)'\)", nile_script)
        dst_match = re.search(r"to\s+(group|endpoint)\('([^']+)'\)", nile_script)
        
        src_type = src_match.group(1)
        src = src_match.group(2).strip()
        
        dst_type = dst_match.group(1)
        dst = dst_match.group(2).strip()
        
        # 3. Extrai Middleboxes (SFC)
        sfc = []
        sfc_line = re.search(r"add\s+((?:middlebox\('[^']+'\)(?:,\s*)?)+)", nile_script)
        if sfc_line:
            sfc = re.findall(r"middlebox\('([^']+)'\)", sfc_line.group(1))
            
        # 4. Extrai Tráfego Permitido (Allow)
        permit = set()
        allow_line = re.search(r"allow\s+((?:traffic\('[^']+'\)(?:,\s*)?)+)", nile_script)
        if allow_line:
            matches = re.findall(r"traffic\('([^']+)'\)", allow_line.group(1))
            for m in matches:
                permit.add(int(m) if m.isdigit() else m)
                
        # 5. Extrai Tráfego Bloqueado (Block)
        deny = set()
        block_line = re.search(r"block\s+((?:traffic\('[^']+'\)(?:,\s*)?)+)", nile_script)
        if block_line:
            matches = re.findall(r"traffic\('([^']+)'\)", block_line.group(1))
            for m in matches:
                deny.add(int(m) if m.isdigit() else m)
                
        filters = set(permit)
        
        # Extrai QoS Parameters
        bandwidth = None
        bw_match = re.search(r"demand\s+bandwidth\('([^']+)'\)", nile_script)
        if bw_match:
            bandwidth = float(bw_match.group(1))
            
        latency = None
        lat_match = re.search(r"demand\s+latency\('([^']+)'\)", nile_script)
        if lat_match:
            latency = float(lat_match.group(1))
            
        packet_loss = None
        pl_match = re.search(r"demand\s+packet_loss\('([^']+)'\)", nile_script)
        if pl_match:
            packet_loss = float(pl_match.group(1))
            
        priority = None
        prio_match = re.search(r"set\s+priority\('([^']+)'\)", nile_script)
        if prio_match:
            priority = int(prio_match.group(1))
            
        return Intent(
            src=src, dst=dst, src_type=src_type, dst_type=dst_type, 
            filters=filters, sfc=sfc, permit=permit, deny=deny,
            bandwidth=bandwidth, latency=latency, packet_loss=packet_loss, priority=priority
        )