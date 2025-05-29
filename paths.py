from aws.configs import URI_OUTPUT, S3_BUCKET, S3_FOLDER

bucket = "unbh-dev-target"
prefix = "medextract_v1"

planilha_cbhpm_path = "pedidos_medicos_labels_cbhpm.xlsx"

model_s3_path = f"s3://{S3_BUCKET}/{S3_FOLDER}/modelo/fine_tuned"
modelo_path = f"{model_s3_path}/image-classification-0027.params"



resultados_negativos = f"{URI_OUTPUT}/resultados_negativos/"
resultados_positivos = f"{URI_OUTPUT}/resultados_positivos/"
resultados_revisao = f"{URI_OUTPUT}/revisar/" 
saida_json_positivos = f"{URI_OUTPUT}/json_positivos/"
saida_dados_extraidos =  f"{URI_OUTPUT}/dados_extraidos/"

saida_callcenter_pendencia = f"{URI_OUTPUT}/dados_extraidos/saida_callcenter_pendencia/"
saida_auditoria_solic = f"{URI_OUTPUT}/dados_extraidos/saida_auditoria_solic/"