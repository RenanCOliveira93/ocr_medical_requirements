import logging
import json
import boto3
import requests
import base64
import botocore
import time
import os
from datetime import datetime, timezone

from botocore.config import Config

from aws.configs import ENV, PROJECT_NAME
from src.handwritten_validation import detect_text_type
from src.classifier import main_double_check, copiar_imagem_para_s3
from src.ocr_extract import TextExtractor
from src.crm_processor import CRMProcessor

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

textract_config = Config(
    connect_timeout=int(os.getenv('TEXTRACT_CONNECT_TIMEOUT', 60)),
    read_timeout=int(os.getenv('TEXTRACT_READ_TIMEOUT', 60)),
    retries={'max_attempts': 0}
)
textract = boto3.client('textract', config=textract_config)

def get_credentials(env: str, project_name: str):
    client = boto3.client("secretsmanager")
    secret_name = f"unbh-{env}-{project_name}-ged"
    
    logger.info(f"Tentando obter credenciais do Secrets Manager: {secret_name}")
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret_dict = json.loads(response["SecretString"])
        username = secret_dict.get("username")
        password = secret_dict.get("password")
        
        if not username or not password:
            logger.error("Credenciais inválidas ou incompletas no Secrets Manager.")
            raise ValueError("Credenciais inválidas ou incompletas no Secrets Manager.")
        
        logger.info(f"Sucesso ao obter o segredo: {secret_name}")
        return username, password
    except Exception as e:
        logger.error(f"Erro ao recuperar a chave {secret_name}: {str(e)}")
        raise e

def authenticate(username, password):
    url = "https://extranet.unimedbh.com.br/openam/json/authenticate"
    headers = {
        "X-OpenAM-Username": username,
        "X-OpenAM-Password": password,
        "Content-Type": "application/json"
    }
    data = {"stage": "ldapService"}
    
    logger.info("Tentando autenticar usuário para gerar token...")
    response = requests.post(url, json=data, headers=headers)
    
    if response.status_code == 200:
        token = response.json().get("tokenId")
        logger.info("Autenticação bem-sucedida, token obtido.")
        return token
    else:
        logger.error(f"Falha na autenticação: {response.text}")
        raise Exception(f"Falha na autenticação: {response.text}")

def validate_token(token):
    url = "https://extranet.unimedbh.com.br/openam/json/sessions?_action=validate"
    headers = {"iPlanetDirectoryPro": token}
    logger.info("Validando token...")
    response = requests.post(url, headers=headers)
    valid = response.status_code == 200 and response.json().get("valid")
    logger.info(f"Token válido? {valid}")
    return valid

try:
    logger.info("Obtendo credenciais do GED para gerar o token global...")
    username, password = get_credentials(ENV, PROJECT_NAME)
    logger.info("Autenticando usuário para gerar o token global...")
    TOKEN = authenticate(username, password)
    
    if not validate_token(TOKEN):
        logger.error("Token inválido após autenticação!")
        raise Exception("Token inválido!")
    
    logger.info("Token global obtido e validado com sucesso!")
except Exception as e:
    logger.error(f"Erro ao gerar o token global: {e}")
    TOKEN = None

def fetch_document(token, nome_origem, document_id, max_retries=1):
    url = ("https://gedweb.unimedbh.com.br/ged/api/principal/consultarDocumentoDigitalizado"
           f"?nomeOrigemDocumentoDigital={nome_origem}&idDocumentoDigitalizado={document_id}")
    headers = {"Cookie": f"iPlanetDirectoryPro={token}"}
    logger.info(f"Buscando documento na URL: {url}")
    
    for attempt in range(max_retries + 1):
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            logger.info("Documento obtido com sucesso.")
            return response.json()
        elif response.status_code in (401, 403) and attempt < max_retries:
            logger.warning("Token inválido ou expirado, tentando renovar...")
            try:
                global TOKEN
                username, password = get_credentials(ENV, PROJECT_NAME)
                TOKEN = authenticate(username, password)
                if not validate_token(TOKEN):
                    logger.error("Novo token inválido após renovação!")
                    raise Exception("Novo token inválido!")
                logger.info("Novo token obtido e validado com sucesso!")
                headers = {"Cookie": f"iPlanetDirectoryPro={TOKEN}"}
            except Exception as e:
                logger.error(f"Falha ao renovar token: {str(e)}")
                raise Exception(f"Falha ao renovar token: {str(e)}")
        else:
            logger.error(f"Falha ao buscar documento: {response.text}")
            raise Exception(f"Falha ao buscar documento: {response.text}")

def call_textract_with_retry(image_bytes, file_name, max_retries=2, backoff_factor=1):
    logger.info(f"Iniciando chamada ao Textract para o arquivo: {file_name}")
    for attempt in range(max_retries):
        try:
            response = textract.detect_document_text(Document={'Bytes': image_bytes})
            logger.info(f"Texto extraído com sucesso para {file_name}")
            if not response.get('Blocks'):
                logger.warning(f"Resposta do Textract vazia para {file_name}")
            else:
                logger.info(f"Blocos de texto encontrados: {len(response.get('Blocks', []))}")
            return response
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['RequestTimeout', 'ThrottlingException']:
                if attempt == max_retries - 1:
                    logger.error(f"Falha após {max_retries} tentativas para {file_name}: {str(e)}")
                    raise
                sleep_time = backoff_factor * (attempt + 1)
                logger.warning(f"{error_code} detectado para {file_name}, tentativa {attempt + 1}/{max_retries}, aguardando {sleep_time}s")
                time.sleep(sleep_time)
            elif error_code in ['InvalidDocumentException', 'UnsupportedDocumentException']:
                logger.error(f"Documento inválido ou não suportado para {file_name}: {str(e)}")
                raise
            else:
                logger.error(f"Erro ao chamar Textract para {file_name}: {str(e)}")
                raise
        except Exception as e:
            logger.error(f"Erro inesperado ao chamar Textract para {file_name}: {str(e)}")
            raise

def evaluate(features: dict):
    start_time = time.time()
    logger.info("Iniciando avaliação do documento...")
    
    if not TOKEN:
        logger.error("Token global inválido ou não foi obtido.")
        return {"error": "Token inválido"}
    
    logger.info(f"Features recebidas: {features}")
    
    nome_origem = features.get("nome_origem_documento_digital")
    document_id = features.get("id_documento_digitalizado")
    nome_paciente_salutaris = features.get("nome_paciente_salutaris", "")
    crm_salutaris = features.get("crm_salutaris", "")
    cro_salutaris = features.get("cro_salutaris", "")
    
    if not nome_origem or not document_id:
        logger.error("Dados de documento ausentes no input.")
        return {"error": "Dados de documento ausentes."}
    
    logger.info(f"Buscando documento {document_id} da origem {nome_origem}...")
    document_data = fetch_document(TOKEN, nome_origem, document_id)
    
    if 'arquivoBinario' not in document_data:
        logger.error("Arquivo binário não encontrado nos dados do documento.")
        return {"error": "Arquivo binário não encontrado"}
    
    arquivo_binario = document_data['arquivoBinario']
    logger.info("Arquivo binário encontrado, decodificando...")
    
    try:
        image_bytes = base64.b64decode(arquivo_binario, validate=True)
        logger.info(f"Arquivo decodificado com sucesso, tamanho: {len(image_bytes)} bytes")
    except base64.binascii.Error as e:
        logger.error(f"Erro ao decodificar base64: {str(e)}")
        return {"error": f"Erro ao decodificar base64: {str(e)}"}
    except Exception as e:
        logger.error(f"Erro inesperado ao decodificar base64: {str(e)}")
        return {"error": f"Erro inesperado ao decodificar base64: {str(e)}"}
    
    file_name = f"{document_id}@{nome_origem}"
    
    if not isinstance(image_bytes, bytes) or len(image_bytes) == 0:
        logger.error(f"Bytes inválidos para o arquivo: {file_name}")
        return {"error": "Bytes inválidos"}
    
    logger.info(f"Chamando Textract para o arquivo: {file_name}")
    textract_start = time.time()
    try:
        textract_response = call_textract_with_retry(image_bytes, file_name)
        logger.info(f"Textract executado em {time.time() - textract_start:.2f}s")
        logger.info(f"Textract response contém {len(textract_response.get('Blocks', []))} blocos")
    except textract.exceptions.InvalidParameterException as e:
        logger.error(f"Erro ao chamar Textract para {file_name}: {str(e)}")
        return {"error": f"Erro ao chamar Textract: {str(e)}"}
    except Exception as e:
        logger.error(f"Erro inesperado ao chamar Textract para {file_name}: {str(e)}")
        return {"error": f"Erro inesperado ao chamar Textract: {str(e)}"}
    
    logger.info(f"Verificando se o documento é manuscrito para {file_name}")
    handwritten_start = time.time()
    is_handwritten = detect_text_type(image_bytes, textract_response=textract_response)
    ind_manuscrito = "HANDWRITING" if is_handwritten else "PRINTED"
    logger.info(f"Documento é manuscrito? {ind_manuscrito}")
    logger.info(f"Verificação de manuscrito executada em {time.time() - handwritten_start:.2f}s")
    
    logger.info(f"Classificando documento como pedido médico para {file_name}")
    classify_start = time.time()
    is_medical_request, char_count, text_raw, is_memed = main_double_check(textract_response=textract_response, original_filename=file_name, image_bytes=image_bytes)
    ind_pedido_medico = "S" if is_medical_request else "N"
    logger.info(f"Classificado como pedido médico? {ind_pedido_medico}")
    logger.info(f"Texto bruto extraído: {text_raw}")
    logger.info(f"Classificação executada em {time.time() - classify_start:.2f}s")
    
    result = {
        "char_count": char_count,
        "is_medical_request": ind_pedido_medico,
        "detect_text_type": ind_manuscrito,
        "text_raw": text_raw,
        "is_memed": is_memed,
        "resultado_medextract": {
            "data_pedido": {"valor": "", "confianca": 0.0},
            "nome_paciente_ocr": {"valor": "", "confianca": 1.0},
            "nome_paciente_existe_ocr": {"valor": "N", "confianca": 0.0},
            "nome_solicitante": {"valor": "", "confianca": 0.0},
            "crm_ocr": {"valor": crm_salutaris, "confianca": 1.0},
            "cro_ocr": {"valor": cro_salutaris, "confianca": 1.0},
            "crm_cro_existe_ocr": {"valor": "N", "confianca": 0.0},
            "itens_exames": []
        },
        "score_medextract": 0.0,
        "score_confiança": 0.0,
        "score_similaridade": 0.0
    }
    
    if is_medical_request:
        logger.info(f"Processando documento como pedido médico para {file_name}")
        extract_start = time.time()
        extractor = TextExtractor()
        extracted_data = extractor.process_image(
            image_bytes=image_bytes,
            textract_response=textract_response,
            nome_paciente_salutaris=nome_paciente_salutaris,
            crm_salutaris=crm_salutaris,
            cro_salutaris=cro_salutaris,
            existing_result=result
        )
        logger.info(f"Extração de texto executada em {time.time() - extract_start:.2f}s")
        
        process_start = time.time()
        processor = CRMProcessor()
        final_result = processor.process(extracted_data)
        logger.info(f"Processamento CRM executado em {time.time() - process_start:.2f}s")
        result.update(final_result)
    else:
        logger.info(f"Documento não classificado como pedido médico, mantendo resultado padrão para {file_name}")
    
    result["is_medical_request"] = ind_pedido_medico
    result["detect_text_type"] = ind_manuscrito
    
    logger.info(f"Resultados finais gerados para {file_name}: {result}")
    logger.info(f"Avaliação concluída em {time.time() - start_time:.2f}s")
    return result