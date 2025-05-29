import boto3
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')
s3_cache = {}  # Cache for S3-loaded images

def check_words_in_image(image_bytes, textract_response=None):
    keywords = {
        "solicito", "solicitado", "solicitação", "pedido", "guia de serviço profissional",
        "serviço auxiliar de diagnóstico e terapia", "sp/sadt", "solicita-se", "solicita-se:",
        "tc", "us", "cid", "ressonancia magnetica", "ultrasom", "ultra som",
        "ultrassonografia", "eletrocardiograma", "ultrassom", "solicita",
        "pede-se", "pede", "peço", "exame", "exames", "requerido"
    }
    keyword_pattern = r'\b(?:' + '|'.join(re.escape(k) for k in keywords) + r')\b'
    
    logger.info("Verificando presença de palavras-chave no texto...")
    try:
        if textract_response is None:
            logger.warning("Resposta do Textract é None, retornando False.")
            return False
        
        extracted_texts = []
        for item in textract_response.get('Blocks', []):
            if item['BlockType'] == 'LINE':
                extracted_texts.append(item['Text'].lower())  # Normalizar aqui
        
        extracted_text = " ".join(extracted_texts)
        logger.info(f"Texto extraído para verificação de palavras-chave: {extracted_text}")
        
        if re.search(keyword_pattern, extracted_text, re.IGNORECASE):
            logger.info("Palavras-chave encontradas no texto.")
            return True
        else:
            logger.info("Nenhuma palavra-chave encontrada no texto.")
            return False
            
    except AttributeError as e:
        logger.error(f"Erro ao acessar resposta do Textract: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Erro inesperado ao processar imagem para palavras-chave: {str(e)}")
        return False

def check_text_length_and_memed(image_bytes, textract_response=None):
    logger.info("Verificando tamanho do texto e presença de 'MEMED'...")
    try:
        if textract_response is None:
            logger.warning("Resposta do Textract é None, retornando valores padrão.")
            return False, "", "N"
        
        extracted_texts = []
        for item in textract_response.get('Blocks', []):
            if item['BlockType'] == 'LINE':
                extracted_texts.append(item['Text'])
        
        text_raw = " ".join(extracted_texts)
        char_count = len(text_raw)
        is_memed = "S" if "memed" in text_raw.lower() else "N"
        
        logger.info(f"Tamanho do texto: {len(text_raw)}, char_count: {char_count}, is_memed: {is_memed}")
        return char_count, text_raw, is_memed
            
    except AttributeError as e:
        logger.error(f"Erro ao acessar resposta do Textract: {str(e)}")
        return False, "", "N"
    except Exception as e:
        logger.error(f"Erro inesperado ao verificar tamanho do texto e MEMED: {str(e)}")
        return False, "", "N"

def load_image_from_s3(s3_path):
    logger.info(f"Carregando imagem do S3: {s3_path}")
    if s3_path in s3_cache:
        logger.info(f"Usando imagem do cache para {s3_path}")
        return s3_cache[s3_path]
    
    try:
        bucket, key = s3_path.replace("s3://", "").split("/", 1)
        response = s3.get_object(Bucket=bucket, Key=key)
        image_content = response['Body'].read()
        s3_cache[s3_path] = image_content
        logger.info(f"Imagem carregada com sucesso, tamanho: {len(image_content)} bytes")
        return image_content
    except s3.exceptions.NoSuchKey as e:
        logger.error(f"Chave S3 não encontrada: {s3_path}, erro: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Erro ao carregar imagem do S3: {str(e)}")
        return None