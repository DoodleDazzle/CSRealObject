from ibm_watson import NaturalLanguageUnderstandingV1
from ibm_watson.natural_language_understanding_v1 import Features, EntitiesOptions, KeywordsOptions
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator

# Watson NLU setup
authenticator = IAMAuthenticator('GgihzRGYw86UTy-jrl0L4j5UYeuiErV4JBJi1PFYZQ3I')
nlu = NaturalLanguageUnderstandingV1(version='2021-08-01', authenticator=authenticator)
nlu.set_service_url('https://api.au-syd.natural-language-understanding.watson.cloud.ibm.com/instances/86660d6c-fce1-4816-a52b-798ba6175cea')

def analyze_text(text):
    try:
        response = nlu.analyze(
            text=text,
            features=Features(
                entities=EntitiesOptions(),
                keywords=KeywordsOptions()
            )
        ).get_result()

        # For security, check for sensitive or risky keywords/entities
        return response
    except Exception as e:
        return {"error": str(e)}
