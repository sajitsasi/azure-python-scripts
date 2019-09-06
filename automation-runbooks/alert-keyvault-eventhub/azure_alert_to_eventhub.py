"""
Azure Automation documentation : https://aka.ms/azure-automation-python-documentation
Azure Python SDK documentation : https://aka.ms/azure-python-sdk
"""

from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
import automationassets
from azure.keyvault import KeyVaultClient, KeyVaultId, KeyVaultAuthentication
from msrestazure.azure_cloud import AZURE_PUBLIC_CLOUD
import sys
import json
import requests


def get_automation_runas_credential(runas_connection):
    """ Returns credentials to authenticate against Azure resoruce manager """
    from OpenSSL import crypto
    from msrestazure import azure_active_directory
    import adal

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    pks12_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pks12_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource_url = AZURE_PUBLIC_CLOUD.endpoints.active_directory_resource_id
    authority_url = AZURE_PUBLIC_CLOUD.endpoints.active_directory + '/' + tenant_id
    context = adal.AuthenticationContext(authority_url)
    return azure_active_directory.AdalAuthentication(
        lambda: context.acquire_token_with_client_certificate(
            resource_url,
            application_id,
            pem_pkey,
            thumbprint)
    )


def get_sas_token(namespace, event_hub, user, key):
    import urllib
    import hmac
    import hashlib
    import base64
    import time

    if not (namespace or event_hub or user or key):
        return None
    uri = urllib.quote_plus("https://{}.servicebus.windows.net/{}".format(namespace, event_hub))
    sas = key.encode('utf-8')
    expiry = str(int(time.time() + 10000))
    string_to_sign = (uri + '\n' + expiry).encode('utf-8')
    signed_hmac_sha256 = hmac.HMAC(sas, string_to_sign, hashlib.sha256)
    signature = urllib.quote(base64.b64encode(signed_hmac_sha256.digest()))
    return "SharedAccessSignature sr={}&sig={}&se={}&skn={}".format(uri, signature, expiry, user)


def get_http_header(namespace, event_hub, user, key):
    if not (namespace or event_hub or user or key):
        return None

    headers = {}
    headers['Content'] = "application/atom+xml;type=entry;charset=utf-8"
    headers['Authorization'] = get_sas_token(namespace, event_hub, user, key)
    headers['Host'] = "{}.servicebus.windows.net".format(namespace)
    return headers


def get_http_params():
    params = {}
    params['timeout'] = 60
    params['api-version']="2014-01"
    return params


def parse_webhook_data(webhook=None):
    if not webhook:
        print("ERROR: no webhook data received!!!")
        return None
    
    start = webhook.find("RequestBody:")
    end   = webhook.find("RequestHeader:")
    if start < 0 or end < 0:
        print("ERROR: couldn't find markers in webhook {}".format(webhook))
        return None
    data = webhook[(start+12):(end-1)]
    return (json.loads(data))


def adal_vault_callback(server, resource, scope):
    """ Returns a token that can be used to authenticate against Azure resources """
    from OpenSSL import crypto
    import adal
    import automationassets

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    sp_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, sp_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    if not resource:
        resource = "https://vault.azure.net"
    if not server:
        server = ("https://login.windows.net/" + tenant_id)
    context = adal.AuthenticationContext(server)
    azure_credential = context.acquire_token_with_client_certificate(
        resource,
        application_id,
        pem_pkey,
        thumbprint)

    # Return the token
    return azure_credential.get('tokenType'), azure_credential.get('accessToken')


def get_kv_secret(client=None, secret_key=None):
    if not secret_key or not client:
        print("ERROR: no secret or client specified")
        return None
    # @TODO: Put your Key Vault information here
    vault_url = 'https://<VAULT_NAME>.vault.azure.net'
    secret = client.get_secret(vault_url, secret_key, KeyVaultId.version_none)
    return secret.value 


def main():
    webhook_data = ""
    for arg in sys.argv:
        webhook_data += arg

    if webhook_data:
        webhook = parse_webhook_data(webhook_data)
    else:
        print("ERROR: no webhook received")
        sys.exit(-1)

# Authenticate to Azure using the Azure Automation RunAs service principal
    runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
    azure_credential = get_automation_runas_credential(runas_connection)

    subscription_id = runas_connection['SubscriptionId']
    # KeyVaultManagement Client to manage KV resources only
    kv_mgmt_client = KeyVaultManagementClient(azure_credential, subscription_id)
    kv_client = KeyVaultClient(KeyVaultAuthentication(adal_vault_callback))

    # Get Event Hub Details from Key Vault
    namespace = get_kv_secret(kv_client, 'EventHubNamespace')
    event_hub = get_kv_secret(kv_client, 'EventHub')
    user      = get_kv_secret(kv_client, 'EventHubKeyName')
    key       = get_kv_secret(kv_client, 'EventHubKey')
    headers = get_http_header(namespace, event_hub, user, key)
    params = get_http_params()

    # Publish event to Event Hub via REST API, for some reason can't use the 
    # Event Hub SDK to directly publish the event
    uri = "https://{}.servicebus.windows.net/{}/messages".format(namespace, event_hub)
    r = requests.post(url=uri, headers=headers, params=params, data=json.dumps(webhook))
    print(r)
    print("sent event to event hub")
    print(json.dumps(webhook, indent=4))


if __name__ == "__main__":
    main()

