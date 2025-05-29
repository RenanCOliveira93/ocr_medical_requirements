import boto3
import logging

from src.ocr_pos_neg import check_words_in_image, check_text_length_and_memed
from src.paths import *

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def main_check_words(image_bytes, textract_response=None):
    logger.info("Verificando palavras-chave no documento...")
    check_words = check_words_in_image(image_bytes, textract_response)
    logger.info(f"Palavras-chave encontradas? {check_words}")
    return check_words

def main_double_check(image_bytes, original_filename=None, textract_response=None):
    logger.info(f"Iniciando double check para o arquivo: {original_filename}")
    char_count, text_raw, is_memed = check_text_length_and_memed(image_bytes, textract_response)
    logger.info(f"Resultado da verificação de tamanho: char_count={char_count}, text_raw='{text_raw}', is_memed={is_memed}")
    
    check_words = main_check_words(image_bytes, textract_response)
    
    img_filename = original_filename
    
    # Classificar como pedido médico se tiver mais de 100 caracteres E palavras-chave
    is_medical_request = char_count >= 100 and check_words
    if is_medical_request:
        destino = f"{resultados_positivos}{img_filename}.png"
    else:
        destino = f"{resultados_negativos}{img_filename}.png"
    
    logger.info(f"Documento classificado como pedido médico: {is_medical_request}, destino: {destino}")
    copiar_imagem_para_s3(image_bytes, destino)
    
    return is_medical_request, char_count, text_raw, is_memed

def copiar_imagem_para_s3(image_bytes, destino_s3):
    try:
        s3 = boto3.client('s3')

        logger.info(f"Destino S3: {destino_s3}")

        if not destino_s3.startswith("s3://"):
            logger.error(f"Caminho de destino inválido: {destino_s3}")
            raise ValueError(f"Caminho de destino inválido: {destino_s3}")

        destino_bucket, destino_key = destino_s3.replace("s3://", "").split("/", 1)

        if not destino_bucket:
            logger.error(f"Nome do bucket inválido: {destino_bucket}")
            raise ValueError(f"Nome do bucket inválido: {destino_bucket}")

        logger.info(f"Fazendo upload dos bytes para S3: {destino_bucket}/{destino_key}")
        s3.put_object(Body=image_bytes, Bucket=destino_bucket, Key=destino_key)

        logger.info("Upload concluído com sucesso.")
        return True

    except Exception as e:
        logger.error(f"Erro ao copiar imagem para S3: {e}")
        return False