# alert-keyvault-eventhub
This script can be placed in an Action Group and run as a runbook

## Acknowledgements
A lot of the code was taken from different sources and put together.  I want to acknowledge the following sites:
1. [Azure-Samples/key-vault-python-authentication](https://github.com/Azure-Samples/key-vault-python-authentication)
2. [Azureautomation/python\_emulated\_assets](https://github.com/azureautomation/python_emulated_assets)
3. [Azure-Samples/key-vault-python-manage](https://github.com/Azure-Samples/key-vault-python-manage)

## Requirements

1. Create an [Azure Automation account](https://docs.microsoft.com/en-us/azure/automation/automation-quickstart-create-account)
2. Import this script as a Python runbook or edit in place by pasting the script.  [More info here](https://docs.microsoft.com/en-us/azure/automation/manage-runbooks)
3. [Import Python2 Modules](https://docs.microsoft.com/en-us/azure/automation/python-packages#runbook)  Note: Use the [Runbook](https://gallery.technet.microsoft.com/scriptcenter/Import-Python-2-packages-57f7d509)  to download the Python2 packages and their dependencies. This makes it far easier than having to download each package one by one (painful!).  Run the following Azure CLI commands to get subscription, and goup info.  Use the Azure Portal to get automation account name
   * ```az account list --query "[].[name, id]" -o table``` and choose the right subscription id
   * ```az group list --subscription <subscription_id from above> -o table``` and choose the automation resource group
   * Get Azure automation account name from the Azure Portal (All Services --> search for 'Automation Accounts')
   * Start runbook to download Python2 packages with parameters:
     - ```-s <subscription_id>```
     - ```-g <resource_group>```
     - ```-a <automation account>```
     - ```-m Azure```
4. [Create an Action Group](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/action-groups) and add the runbook from #2 above as an action
5. Setup an [alert](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-metric)
6. [Create an Event Hubs Namespace and event hub](https://docs.microsoft.com/en-us/azure/event-hubs/event-hubs-quickstart-cli) and capture the following data:
   * EventHubNamespace
   * EventHub
   * EventHubKeyName (from Event Hub --> Shared Access Policies --> Policy Name)
   * EventHubKey (from Event Hub --> Shared Access Policies --> Primary Key)
7. [Create a Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/quick-create-cli), run the following commands:
   * Create Key Vault with ```az keyvault create --name <key_vault_name> --resource-group <resource_group_name> --location <location>```
   * Add EventHubNamespace secret ```az keyvault secret set --vault-name <key_vault_name> --name "EventHubNamespace" --value <event_hub_namespace_name>```
   * Add EventHub secret ```az keyvault secret set --vault-name <key_vault_name> --name "EventHub" --value <event_hub_name>```
   * Add EventHubKeyName secret ```az keyvault secret set --vault-name <key_vault_name> --name "EventHubKeyName" --value <event_hub_policy_name>```
   * Add EventHubKey secret ```az keyvault secret set --vault-name <key_vault_name> --name "EventHubKey" --value <event_hub_policy_primary_key>```
8. Modify runbook function ```get_kv_secret(client=None, secret_key=None)``` and replace ```<VAULT_NAME>``` in line ```vault_url = 'https://<VAULT-NAME>.vault.azure.net``` with your vault name
9. Save and Publish your runbook



## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

