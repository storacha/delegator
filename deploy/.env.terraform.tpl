# copy to .env.terraform and set missing vars
TF_WORKSPACE= # your name here
TF_VAR_app=registrar
TF_VAR_did= # did for your env
TF_VAR_private_key= # private_key or your env -- do not commit to repo!
TF_VAR_allowed_account_id=505595374361
TF_VAR_region=us-east-2
TF_VAR_indexing_service_proof= # enter a value for REGISTRAR_DELEGATOR_INDEXING_SERVICE_PROOF secret
TF_VAR_egress_tracking_service_proof= # enter a value for REGISTRAR_DELEGATOR_EGRESS_TRACKING_SERVICE_PROOF secret
TF_VAR_contract_transactor_key= # enter a value for REGISTRAR_CONTRACT_TRANSACTOR_KEY secret
TF_VAR_cloudflare_zone_id= # enter the cloudflare zone id
CLOUDFLARE_API_TOKEN= # enter a cloudflare api token
