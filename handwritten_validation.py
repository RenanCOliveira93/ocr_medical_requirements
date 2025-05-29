import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def detect_text_type(image_bytes, textract_response=None, handwriting_threshold=0.5):
    """
    Determina se o texto em um documento é manuscrito ou digital (impresso) usando a resposta do Textract.
    
    Args:
        image_bytes: Bytes da imagem do documento (mantido por compatibilidade, não usado).
        textract_response: Resposta do AWS Textract contendo blocos de texto.
        handwriting_threshold: Proporção mínima de blocos 'HANDWRITING' para classificar como manuscrito (padrão: 0.5).
    
    Returns:
        bool: True se o documento for predominantemente manuscrito, False se for digital, None se não for possível determinar.
    """
    logger.info("Iniciando detecção de tipo de texto (manuscrito vs. digital)...")

    # Validar textract_response
    if not textract_response or 'Blocks' not in textract_response:
        logger.warning("Resposta do Textract inválida ou vazia, não é possível determinar o tipo de texto.")
        return None

    # Contar blocos HANDWRITING e PRINTED
    handwriting_count = 0
    printed_count = 0
    for item in textract_response.get('Blocks', []):
        if item['BlockType'] == 'LINE' and 'TextType' in item:
            if item['TextType'] == 'HANDWRITING':
                handwriting_count += 1
            elif item['TextType'] == 'PRINTED':
                printed_count += 1

    total_blocks = handwriting_count + printed_count
    if total_blocks == 0:
        logger.warning("Nenhum bloco de texto relevante encontrado (HANDWRITING ou PRINTED).")
        return None

    # Calcular proporção de blocos HANDWRITING
    handwriting_ratio = handwriting_count / total_blocks
    logger.info(f"Proporção de blocos HANDWRITING: {handwriting_ratio:.2f}, Total blocos: {total_blocks}")

    # Determinar tipo de texto com base no threshold
    is_handwritten = handwriting_ratio >= handwriting_threshold
    logger.info(f"Documento classificado como {'manuscrito' if is_handwritten else 'digital'} "
                f"(threshold: {handwriting_threshold}, proporção: {handwriting_ratio:.2f})")
    return is_handwritten