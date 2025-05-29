import re
from datetime import datetime
from rapidfuzz import fuzz, process
from src.cbhpm_dict import cod_cbhpm_dict
import logging
import unicodedata

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class TextExtractor:
    def __init__(self):
        self.client_keywords = {"para:", "paciente:"}
        self.month_map = {
            'janeiro': '01', 'fevereiro': '02', 'março': '03', 'abril': '04',
            'maio': '05', 'junho': '06', 'julho': '07', 'agosto': '08',
            'setembro': '09', 'outubro': '10', 'novembro': '11', 'dezembro': '12'
        }
        self.cbhpm_dict = cod_cbhpm_dict
        self.fuzzy_cache = {}

        # Dicionário de padronização para exames
        self.STANDARD_EXAM_MAPPING = {
            "Ultrassom": "US",
            "Ultra som": "US",
            "Ultrassonografia": "US",
            "USG": "US",
            "Ultra-som": "US",
            "US": "US",
            "Ultrossm": "US",
            "ULTRA": "US",
            "Tomografia Computadorizada": "TC",
            "TC": "TC",
            "TOMOGRAFIA": "TC",
            "ANGIOTOMOGRAFIA": "ANGIOTOMOGRAFIA",
            "Ressonância Magnética": "RM",
            "RNM": "RM",
            "RM": "RM",
            "ANGIO RM": "ANGIO RM",
            "RESSONÂNCIA": "RM",
            "Mamografia": "Mamografia",
            "Ecocardiograma": "Ecocardiograma",
            "Ecodoppler": "Ecodoppler",
            "RX": "RX",
            "Raio X": "RX",
            "Raio-X": "RX",
            "Endoscopia": "Endoscopia",
            "Colonoscopia": "Colonoscopia",
            "Ecoendoscopia": "Ecoendoscopia",
            "Laringoscopia": "Laringoscopia",
            "Nasofibrolaringoscopia": "Nasofibrolaringoscopia",
            "Video Endoscopia": "Video Endoscopia",
            "Video-Endoscopia": "Video Endoscopia",
            "Mamotomia": "Mamotomia",
            "Biopsia": "Biopsia",
            "Punção": "Punção",
            "Puncao": "Punção",
            "Cintilografia": "Cintilografia",
            "Holter": "Holter",
            "Mapa": "Mapa",
            "Ergométrico": "Ergométrico",
            "Teste": "Teste",
            "Espirometria": "Espirometria",
            "Eletroencefalograma": "Eletroencefalograma",
            "ECG": "ECG",
            "Eletrocardiograma": "ECG",
            "Audiometria": "Audiometria",
            "Urodinâmica": "Urodinâmica",
            "Faringolaringoscopia": "Faringolaringoscopia",
            "Retossigmoidoscopia": "Retossigmoidoscopia",
            "Broncoscopia": "Broncoscopia",
            "Cistoscopia": "Cistoscopia",
            "Densitometria": "Densitometria",
            "Hemograma": "Hemograma",
            "PCR": "PCR",
            "Creatinina": "Creatinina",
            "Ácido": "Ácido",
            "Triglicérides": "Triglicérides",
            "Triglicerídeos": "Triglicérides",
            "TGP": "TGP",
            "Alcalina": "Alcalina",
            "GGT": "GGT",
            "Eletroforese": "Eletroforese",
            "Glicohemoglobina": "Glicohemoglobina",
            "T41": "T41",
            "Anti-Hbs": "Anti-Hbs",
            "Anti-HCV": "Anti-HCV",
            "B12": "B12",
            "Ferritina": "Ferritina",
            "Urina": "Urina",
            "Albumina": "Albumina",
            "Polissonografia": "POLISSONOGRAFIA",
            "HEMOGRAMA": "HEMOGRAMA",
            "UREIA": "UREIA",
            "CREATININA": "CREATININA"
        }

        # Regex atualizado para capturar nomes de exames
        self.exam_name_pattern = re.compile(
            r'\b('
            r'US|ULTRA[-\s]?SONOGRAFIA|ULTRASSOM|DOPPLER|TC|TOMOGRAFIA|ANGIOTOMOGRAFIA|RM|ANGIO\s?RM|'
            r'ECOCARDIOGRAMA|ECODOPPLER|RX|RAIO[-\s]?X|ENDOSCOPIA|COLONOSCOPIA|ECOENDOSCOPIA|'
            r'LARINGOSCOPIA|NASOFIBROLARINGOSCOPIA|VIDEO[-\s]?ENDOSCOPIA|MAMOTOMIA|BIOPSIA|PUNCAO|'
            r'CINTILOGRAFIA|HOLTER|MAPA|ERGOMETRICO|TESTE|ESPIROMETRIA|ELETROENCEFALOGRAMA|ECG|'
            r'ELETROCARDIOGRAMA|AUDIOMETRIA|URODINAMICA|FARINGOLARINGOSCOPIA|RETOSSIGMOIDOSCOPIA|'
            r'BRONCOSCOPIA|CISTOSCOPIA|MAMOGRAFIA|Ultrossm|USG|US|RNM|ULTRA|RESSONÂNCIA|DENSITOMETRIA|'
            r'Hemograma|PCR|creatinina|ácido|Triglicérides|TGP|alcalina|GGT|eletroforese|glicohemoglobina|'
            r'T41|anti-Hbs|anti-HCV|B12|ferritina|Urina|albumina|Polissonografia|HEMOGRAMA|UREIA|CREATININA|'
            r')\b'
            r'(?:\s+[\wáéíóúãõç-]+)*',
            re.IGNORECASE
        )

    def normalize_text(self, text):
        text = ''.join(c for c in unicodedata.normalize('NFD', text) if unicodedata.category(c) != 'Mn')
        text = text.lower()
        text = re.sub(r'be4a', 'beta', text)
        text = re.sub(r'rnm', 'ressonância magnética', text)
        text = re.sub(r't3l', 't3 livre', text)
        text = re.sub(r't4l', 't4 livre', text)
        text = re.sub(r'trigricerides', 'triglicerídeos', text)
        return text.strip()

    def standardize_exam(self, exam_text: str) -> str:
        """
        Padroniza apenas a palavra-chave do exame, preservando o restante do texto.
        """
        exam_text_normalized = self.normalize_text(exam_text)
        for key in self.STANDARD_EXAM_MAPPING:
            # Cria um padrão regex para encontrar a chave no texto
            pattern = r'\b' + re.escape(key.lower()) + r'\b'
            if re.search(pattern, exam_text_normalized, re.IGNORECASE):
                # Substitui apenas a palavra-chave pelo termo padronizado
                standardized_term = self.STANDARD_EXAM_MAPPING[key]
                # Preserva a capitalização do texto original para a palavra-chave
                match = re.search(pattern, exam_text, re.IGNORECASE)
                if match:
                    original_key = match.group(0)
                    return exam_text.replace(original_key, standardized_term)
        return exam_text  # Retorna o texto original se não houver mapeamento

    def extract_text(self, textract_response):
        logger.info("Extracting text from Textract response using block-based separation...")
        if not textract_response or 'Blocks' not in textract_response:
            logger.error("Invalid or empty Textract response")
            raise ValueError("Invalid or empty Textract response")
        
        lines = []
        confidences = []
        for item in textract_response.get('Blocks', []):
            if item['BlockType'] == 'LINE':
                lines.append(item['Text'])
                confidences.append(item['Confidence'] / 100.0)
        
        if not lines:
            logger.warning("No text extracted from Textract response")
            return "", [], []
        
        full_text = " ".join(lines)
        logger.info(f"Full text extracted: {full_text}")
        logger.info(f"Number of lines: {len(lines)}, Confidences: {confidences}")
        return full_text, lines, confidences

    def extract_info(self, texts, confidences, image_bytes=None, nome_paciente_salutaris="", crm_salutaris="", cro_salutaris="", validate_with_ocr=True, existing_result=None):
        logger.info("Starting information extraction from OCR text...")
        resultado = existing_result if existing_result is not None else {}
        
        defaults = {
            "is_medical_request": "S",
            "text_raw": texts[0] if texts else "",
            "resultado_medextract": {
                "data_pedido": {"valor": "", "confianca": 0.0},
                "nome_paciente_ocr": {"valor": "", "confianca": 0.0},
                "nome_paciente_existe_ocr": {"valor": "N", "confianca": 0.0},
                "nome_solicitante": {"valor": "", "confianca": 0.0},
                "crm_ocr": {"valor": "", "confianca": 0.0},
                "cro_ocr": {"valor": cro_salutaris, "confianca": 0.0},
                "crm_cro_existe_ocr": {"valor": "N", "confianca": 0.0},
                "itens_exames": []
            },
            "score_medextract": 0.0,
            "score_confiança": 0.0,
            "score_similaridade": 0.0
        }
        
        if 'resultado_medextract' not in resultado:
            resultado['resultado_medextract'] = defaults['resultado_medextract'].copy()
        else:
            for key, value in defaults['resultado_medextract'].items():
                if key not in resultado['resultado_medextract']:
                    resultado['resultado_medextract'][key] = value.copy()
        
        for key, value in defaults.items():
            if key not in resultado:
                resultado[key] = value

        exam_list = []
        dates_found = []
        full_text = texts[0] if texts else ""
        full_text_lower = self.normalize_text(full_text)
        lines = texts[1] if texts else []
        line_confidences = confidences if confidences else []

        name_pattern = r'([A-ZÁÉÍÓÚÃÕÇ][a-záéíóúãõç]+(?:\s+[A-ZÁÉÍÓÚÃÕÇ][a-záéíóúãõç]+){1,4})'
        potential_names = re.findall(name_pattern, full_text)

        selected_solicitante = None
        solicitante_confidence = 0.0

        cbhpm_pattern = r'\b4\d{7}(?=\s|$|[A-Z])'
        tuss_pattern = r'\bTUSS[:\s]*(\d{8})\b'

        crm_validated = False
        cro_validated = False
        name_validated = False
        crm_cro_confidence = 0.0

        if validate_with_ocr and nome_paciente_salutaris and isinstance(nome_paciente_salutaris, str):
            try:
                first_name = nome_paciente_salutaris.split()[0].upper()
                name_pattern_ocr = rf'\b{re.escape(first_name)}\b'
                for i, line in enumerate(lines):
                    if i >= len(line_confidences):
                        logger.warning(f"Confidence index missing for line {i}")
                        continue
                    line_upper = line.upper()
                    name_match = re.search(name_pattern_ocr, line_upper, re.IGNORECASE)
                    if name_match:
                        name_validated = True
                        resultado['resultado_medextract']['nome_paciente_existe_ocr']['valor'] = "S"
                        resultado['resultado_medextract']['nome_paciente_existe_ocr']['confianca'] = line_confidences[i]
                        full_name_match = re.search(name_pattern, line, re.IGNORECASE)
                        if full_name_match:
                            resultado['resultado_medextract']['nome_paciente_ocr']['valor'] = full_name_match.group(0)
                            resultado['resultado_medextract']['nome_paciente_ocr']['confianca'] = line_confidences[i]
                        logger.info(f"Patient first name validated: {first_name}, confidence: {line_confidences[i]}")
                        break
                if not name_validated:
                    resultado['resultado_medextract']['nome_paciente_existe_ocr']['valor'] = "N"
                    resultado['resultado_medextract']['nome_paciente_ocr']['valor'] = ""  # Define como vazio se não encontrado
                    resultado['resultado_medextract']['nome_paciente_ocr']['confianca'] = 0.0
                    logger.info(f"Patient first name not found: {first_name}")
            except Exception as e:
                logger.error(f"Error validating patient name: {str(e)}")
                resultado['resultado_medextract']['nome_paciente_existe_ocr']['valor'] = "N"
                resultado['resultado_medextract']['nome_paciente_existe_ocr']['confianca'] = 0.0
                resultado['resultado_medextract']['nome_paciente_ocr']['valor'] = ""  # Define como vazio em caso de erro
                resultado['resultado_medextract']['nome_paciente_ocr']['confianca'] = 0.0

        if validate_with_ocr and crm_salutaris:
            for i, line in enumerate(lines):
                if i >= len(line_confidences):
                    logger.warning(f"Confidence index missing for line {i}")
                    continue
                crm_match = re.search(r'\bCRM(?:[-/:]?\s*(?:MG|mg))?\s*(?:[-:]\s*)?(\d{2,6}(?:\.\d{3})?)(?:\s*[-:]\s*MG)?\b', line, re.IGNORECASE)
                if crm_match:
                    crm_value = crm_match.group(1).replace('.', '')
                    if crm_value == crm_salutaris:
                        crm_validated = True
                        resultado['resultado_medextract']['crm_ocr']['valor'] = crm_value
                        resultado['resultado_medextract']['crm_ocr']['confianca'] = line_confidences[i]
                        crm_cro_confidence = max(crm_cro_confidence, line_confidences[i])
                        logger.info(f"CRM validated: {crm_value}, confidence: {line_confidences[i]}")
                        break
            if not crm_validated:
                logger.info(f"CRM not found: {crm_salutaris}")

        if validate_with_ocr and cro_salutaris:
            for i, line in enumerate(lines):
                if i >= len(line_confidences):
                    logger.warning(f"Confidence index missing for line {i}")
                    continue
                cro_match = re.search(r'\bCRO(?:[-/:]?\s*(?:MG|mg))?\s*(?:[-:]\s*)?(\d{2,6})\b', line, re.IGNORECASE)
                if cro_match:
                    cro_value = cro_match.group(1)
                    if cro_value == cro_salutaris:
                        cro_validated = True
                        resultado['resultado_medextract']['cro_ocr']['valor'] = cro_value
                        resultado['resultado_medextract']['cro_ocr']['confianca'] = line_confidences[i]
                        crm_cro_confidence = max(crm_cro_confidence, line_confidences[i])
                        logger.info(f"CRO validated: {cro_value}, confidence: {line_confidences[i]}")
                        break
            if not cro_validated:
                logger.info(f"CRO not found: {cro_salutaris}")

        if crm_validated or cro_validated:
            resultado['resultado_medextract']['crm_cro_existe_ocr']['valor'] = "S"
            resultado['resultado_medextract']['crm_cro_existe_ocr']['confianca'] = crm_cro_confidence
        else:
            resultado['resultado_medextract']['crm_cro_existe_ocr']['valor'] = "N"

        added_exams = set()
        valid_exams = []

        # Estratégia 1: Extração de exames por códigos TUSS ou CBHPM
        cbhpm_found = False
        for i, line in enumerate(lines):
            tuss_match = re.search(tuss_pattern, line, re.IGNORECASE)
            if tuss_match:
                cbhpm_code = tuss_match.group(1)
                try:
                    cbhpm_code = int(cbhpm_code)
                    if cbhpm_code in self.cbhpm_dict:
                        exam_desc = self.cbhpm_dict[cbhpm_code]
                        exam_key = (cbhpm_code, exam_desc)
                        if exam_key not in added_exams:
                            valid_exams.append({
                                "exame": exam_desc,
                                "exame_ocr": line,
                                "codigo_cbhpm": str(cbhpm_code),
                                "score_similaridade_exame": 1.0,
                                "quantidade": "1",
                                "confianca": line_confidences[i] if i < len(line_confidences) else 0.0
                            })
                            added_exams.add(exam_key)
                            cbhpm_found = True
                            logger.info(f"TUSS found: {cbhpm_code}, exam: {exam_desc}")
                except ValueError:
                    logger.warning(f"Invalid TUSS code: {cbhpm_code}")
                    continue

            cbhpm_match = re.search(cbhpm_pattern, line)
            if cbhpm_match:
                cbhpm_code = cbhpm_match.group(0)
                try:
                    cbhpm_code = int(cbhpm_code)
                    if cbhpm_code in self.cbhpm_dict:
                        exam_desc = self.cbhpm_dict[cbhpm_code]
                        exam_key = (cbhpm_code, exam_desc)
                        if exam_key not in added_exams:
                            valid_exams.append({
                                "exame": exam_desc,
                                "exame_ocr": line,
                                "codigo_cbhpm": str(cbhpm_code),
                                "score_similaridade_exame": 1.0,
                                "quantidade": "1",
                                "confianca": line_confidences[i] if i < len(line_confidences) else 0.0
                            })
                            added_exams.add(exam_key)
                            cbhpm_found = True
                            logger.info(f"CBHPM code found: {cbhpm_code}, exam: {exam_desc}")
                except ValueError:
                    logger.warning(f"Invalid CBHPM code: {cbhpm_code}")
                    continue

        # Estratégia 2: Executada apenas se nenhum código CBHPM foi encontrado
        if not cbhpm_found:
            logger.info("Iniciando Estratégia 2: Extração de exames por nome")
            for i, line in enumerate(lines):
                line_lower = self.normalize_text(line)
                logger.info(f"Processando linha {i}: {line_lower}")
                for match in self.exam_name_pattern.finditer(line_lower):
                    # Captura a palavra-chave e o nome completo do exame
                    keyword = match.group(1)
                    full_exam_text = match.group(0).strip()
                    logger.info(f"Exame potencial encontrado: keyword={keyword}, full_text={full_exam_text}")

                    # Filtro para evitar exames curtos ou e-mails
                    if len(full_exam_text) < 3:
                        logger.info(f"Exame '{full_exam_text}' descartado: muito curto")
                        continue
                    if re.search(r'[@]|\b(email|gmail|hotmail|yahoo)\b', full_exam_text, re.IGNORECASE):
                        logger.info(f"Exame '{full_exam_text}' descartado: contém e-mail")
                        continue

                    # Padroniza o nome do exame, preservando o texto adicional
                    standardized_exam = self.standardize_exam(full_exam_text)
                    logger.info(f"Exame padronizado: {standardized_exam}")

                    # Fuzzy matching com o dicionário CBHPM
                    fuzzy_result = process.extractOne(standardized_exam, self.cbhpm_dict.values(), score_cutoff=52)
                    confidence = line_confidences[i] if i < len(line_confidences) else 0.5

                    if fuzzy_result:
                        exam_name, score, _ = fuzzy_result
                        cbhpm_code = next((k for k, v in self.cbhpm_dict.items() if v == exam_name), "")
                        exam_key = (cbhpm_code, exam_name)
                        if exam_key not in added_exams:
                            valid_exams.append({
                                "exame": exam_name,
                                "exame_ocr": full_exam_text,
                                "codigo_cbhpm": str(cbhpm_code),
                                "score_similaridade_exame": score / 100.0,
                                "quantidade": "1",
                                "confianca": confidence
                            })
                            added_exams.add(exam_key)
                            logger.info(f"Fuzzy match encontrado: exame={exam_name}, código={cbhpm_code}, score={score}")
                    else:
                        logger.info(f"Sem correspondência no CBHPM para '{standardized_exam}', descartando")

        # Filtra apenas exames com código CBHPM válido
        resultado['resultado_medextract']['itens_exames'] = [exam for exam in valid_exams if exam['codigo_cbhpm']]

        for i, line in enumerate(lines):
            if i >= len(line_confidences):
                logger.warning(f"Confidence index missing for line {i}")
                continue
            line_lower = self.normalize_text(line)
            date_match = re.search(
                r'(?:data\s*(?:da\s*solicitação)?\s*)?(?:(?:belo\s*horizonte|bh),?\s*)?'
                r'(?:(\d{1,2})\s*(?:de\s+)?([a-zçãõ]+)\s*(?:de\s+)?(\d{2,4})|(\d{1,2})\s*/\s*(\d{1,2})\s*/\s*(\d{2,4}))',
                line_lower, re.IGNORECASE
            )
            if date_match:
                try:
                    if date_match.group(1):
                        day, month_name, year = date_match.group(1), date_match.group(2), date_match.group(3)
                        month = self.month_map.get(month_name.lower())
                        if not month:
                            logger.warning(f"Invalid month: {month_name}")
                            continue
                    else:
                        day, month, year = date_match.group(4), date_match.group(5), date_match.group(6)
                    
                    if len(year) == 2:
                        year = "20" + year
                    elif year.startswith("00"):
                        year = "20" + year[2:]
                    
                    date_str = f"{int(day):02d}/{int(month):02d}/{year}"
                    date_obj = datetime.strptime(date_str, '%d/%m/%Y')
                    dates_found.append((date_obj, date_str, line_confidences[i]))
                    logger.info(f"Date found: {date_str}, confidence: {line_confidences[i]}")
                except ValueError as e:
                    logger.warning(f"Error parsing date: {str(e)}")
                    continue

            if re.match(r'^(Dra?|Dr)\.?\s', line):
                solicitante_match = re.search(r'^(Dra?|Dr)\.?\s+([A-ZÁÉÍÓÚÃÕÇ][a-záéíóúãõç]+(?:\s+[A-ZÁÉÍÓÚÃÕÇ][a-záéíóúãõç]+){1,4})', line, re.IGNORECASE)
                if solicitante_match:
                    selected_solicitante = solicitante_match.group(0)
                    solicitante_confidence = line_confidences[i]
                    resultado['resultado_medextract']['nome_solicitante']['valor'] = selected_solicitante
                    resultado['resultado_medextract']['nome_solicitante']['confianca'] = solicitante_confidence
                    logger.info(f"Solicitor name found: {selected_solicitante}, confidence: {solicitante_confidence}")

        if dates_found:
            try:
                dates_found.sort(key=lambda x: x[0], reverse=True)
                most_recent_date, date_str, confidence = dates_found[0]
                date_obj = datetime.strptime(date_str, '%d/%m/%Y')
                formatted_date = date_obj.strftime('%Y-%m-%d')
                resultado['resultado_medextract']['data_pedido']['valor'] = formatted_date
                resultado['resultado_medextract']['data_pedido']['confianca'] = confidence
                logger.info(f"Most recent date selected: {formatted_date}")
            except ValueError as e:
                logger.error(f"Error formatting most recent date: {str(e)}")

        confidences = [
            resultado['resultado_medextract']['data_pedido']['confianca'],
            resultado['resultado_medextract']['nome_paciente_ocr']['confianca'],
            resultado['resultado_medextract']['nome_paciente_existe_ocr']['confianca'],
            resultado['resultado_medextract']['nome_solicitante']['confianca'],
            resultado['resultado_medextract']['crm_ocr']['confianca'],
            resultado['resultado_medextract']['cro_ocr']['confianca'],
            resultado['resultado_medextract']['crm_cro_existe_ocr']['confianca']
        ]
        confidences.extend(item['confianca'] for item in valid_exams if 'confianca' in item)
        score_confiança = sum(conf for conf in confidences if conf > 0) / max(1, len([conf for conf in confidences if conf > 0])) if confidences else 0.0
        resultado['score_confiança'] = score_confiança
        logger.info(f"Confidence score calculated: {score_confiança}")

        score_similaridade = sum(item['score_similaridade_exame'] for item in valid_exams if 'score_similaridade_exame' in item) / len(valid_exams) if valid_exams else 0.0
        resultado['score_similaridade'] = score_similaridade
        logger.info(f"Similarity score calculated: {score_similaridade}")

        # Cálculo do score_medextract
        score_medextract = 0.0
        if resultado['resultado_medextract']['data_pedido']['valor']:
            score_medextract += 0.1
        if resultado['resultado_medextract']['crm_ocr']['valor'] or resultado['resultado_medextract']['cro_ocr']['valor']:
            score_medextract += 0.2
        if resultado['resultado_medextract']['itens_exames']:
            score_medextract += 0.3
        resultado['score_medextract'] = score_medextract
        logger.info(f"Medextract score calculated: {score_medextract}")

        logger.info(f"Final exam list: {resultado['resultado_medextract']['itens_exames']}")
        return resultado

    def process_image(self, image_bytes=None, textract_response=None, nome_paciente_salutaris="", crm_salutaris="", cro_salutaris="", validate_with_ocr=True, existing_result=None):
        logger.info("Processing image for text extraction...")
        try:
            full_text, lines, confidences = self.extract_text(textract_response)
            return self.extract_info((full_text, lines), confidences, image_bytes, nome_paciente_salutaris, crm_salutaris, cro_salutaris, validate_with_ocr, existing_result)
        except AttributeError as e:
            logger.error(f"Error accessing Textract response: {str(e)}")
            raise
        except ValueError as e:
            logger.error(f"Validation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error processing image: {str(e)}")
            raise