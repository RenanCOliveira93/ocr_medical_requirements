import logging
from src.cbhpm_dict import cod_cbhpm_dict
from rapidfuzz import process

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class CRMProcessor:
    def __init__(self):
        self.cbhpm_dict = cod_cbhpm_dict
        self.valid_cbhpm_codes = set(self.cbhpm_dict.keys())

    def process_data(self, extracted_data, crm_salutaris=""):
        logger.info("Iniciando processamento no CRMProcessor...")
        
        if not extracted_data or 'resultado_medextract' not in extracted_data:
            logger.error("Dados extraídos inválidos ou ausentes.")
            return {
                'resultado_medextract': {'itens_exames': []},
                'score_medextract': 0.0,
                'score_confiança': 0.0,
                'score_similaridade': 0.0
            }

        cro = extracted_data.get('resultado_medextract', {}).get('cro_ocr', {}).get('valor', '')
        itens_exames = extracted_data.get('resultado_medextract', {}).get('itens_exames', [])
        data_pedido = extracted_data.get('resultado_medextract', {}).get('data_pedido', {}).get('valor', '')

        valid_exams = []
        for item in itens_exames:
            codigo_cbhpm = item.get('codigo_cbhpm')
            exame_nome = item.get('exame')
            try:
                codigo_cbhpm_int = int(codigo_cbhpm) if codigo_cbhpm else None
                if codigo_cbhpm and codigo_cbhpm_int in self.valid_cbhpm_codes:
                    valid_exams.append({
                        "exame": item['exame'],
                        "exame_ocr": item['exame_ocr'],
                        "codigo_cbhpm": item['codigo_cbhpm'],
                        "score_similaridade_exame": item['score_similaridade_exame'],
                        "quantidade": "1",
                        "confianca": item['confianca']
                    })
                else:
                    # Tentativa de fuzzy match se não houver código CBHPM
                    if exame_nome:
                        resultado = process.extractOne(exame_nome, self.cbhpm_dict.values(), score_cutoff=52)
                        if resultado:
                            codigo_match = next((k for k, v in self.cbhpm_dict.items() if v == resultado[0]), None)
                            if codigo_match:
                                valid_exams.append({
                                    "exame": resultado[0],
                                    "exame_ocr": item['exame_ocr'],
                                    "codigo_cbhpm": str(codigo_match),
                                    "score_similaridade_exame": resultado[1] / 100.0,
                                    "quantidade": "1",
                                    "confianca": item['confianca']
                                })
                        else:
                            # Preservar o exame mesmo sem correspondência no CBHPM
                            valid_exams.append({
                                "exame": exame_nome,
                                "exame_ocr": item['exame_ocr'],
                                "codigo_cbhpm": "",
                                "score_similaridade_exame": 0.0,
                                "quantidade": "1",
                                "confianca": item['confianca']
                            })
                            logger.info(f"Exame preservado sem código CBHPM: {exame_nome}")
                    else:
                        logger.warning(f"Sem match para exame: {exame_nome}")
            except (ValueError, TypeError):
                logger.warning(f"Código CBHPM inválido: {codigo_cbhpm}")
                continue

        unique_exams = {
            (exam['codigo_cbhpm'], exam['exame']): exam
            for exam in sorted(valid_exams, key=lambda x: x['confianca'], reverse=True)
        }
        valid_exams = list(unique_exams.values())
        logger.info(f"Exames após remoção de duplicatas: {valid_exams}")

        if not valid_exams and itens_exames:
            valid_exams = [item for item in itens_exames if item.get("exame")]
            logger.info("Exames mantidos mesmo sem CBHPM válido.")

        extracted_data['resultado_medextract']['itens_exames'] = valid_exams

        score_medextract = 0.2 # CRM ja existe na requisição
        if data_pedido:
            score_medextract += 0.1
        
        if valid_exams:
            if any(item['codigo_cbhpm'] for item in valid_exams):
                score_medextract += 0.7
            else:
                score_medextract += 0.0

        score_medextract = round(score_medextract, 1)
        if score_medextract > 1.0:
            score_medextract = 1.0
        logger.info(f"Score medextract calculado: {score_medextract}")

        score_confiança = sum(item['confianca'] for item in valid_exams) / max(1, len(valid_exams))
        score_similaridade = sum(item['score_similaridade_exame'] for item in valid_exams) / max(1, len(valid_exams))
        logger.info(f"Score confiança: {score_confiança}, Score similaridade: {score_similaridade}")

        extracted_data['score_medextract'] = score_medextract
        extracted_data['score_confiança'] = score_confiança
        extracted_data['score_similaridade'] = score_similaridade
        logger.info("Processamento no CRMProcessor concluído.")
        return extracted_data

    def process(self, extracted_data, crm_salutaris=""):
        return self.process_data(extracted_data, crm_salutaris)