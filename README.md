# CYBER LOGS CLASSIFIER

## Règles déterministes (pré filtre avant LLM)
-Brute Force SSH/Auth
log_source = authentication + status = failure + auth_method = ssh + > 10 occurrences / même IP / 5 min
données : 185.220.101.42 avec 624 failures — cas réel 

-Credential Stuffing (multi-comptes)
Même source_ip + status = failure + > 5 username différents / 5 min
Différent du brute force : ici l'attaquant teste plein de comptes, pas le même

-Impossible Travel
Même username + status = success + 2 geolocation_country différents en < 1h
Ex : login depuis FR puis CN dans la même heure → compte compromis quasi certain

-Pays 100% failure
geolocation_country ∈ {CN, RU, KP, IR} + status = failure → score de risque max
données confirment : ces 4 pays ont un taux d'échec de 100%


## Règles contextuelles (enrichissement avant LLM)
-Baseline comportementale utilisateur (UEBA) ManageEngine
Calculer le nb moyen de logins / heure par username → alerter si > moyenne + 3σ
Même logique sur bytes_sent réseau par IP → détecte exfiltration ou DDoS

-Enrichissement géo + asset Secure
Croiser source_ip avec la liste des IPs internes connues (10.x.x.x)
Une IP interne qui fait du SQLi ou du path traversal = mouvement latéral post-compromission, bien plus grave qu'une IP externe

-Seuils différenciés par type de compte ThinkCloudly
auth_method = api_key → tolérance plus haute sur les failures (les scripts ratent souvent)
auth_method = password + hostname = ldap-prod-01 → seuil bas, très sensible

-Suppression des faux positifs récurrents (whitelist dynamique) CyberDefenders
user_agent = python-requests depuis une IP interne + URI de monitoring connu → ignorer
logs ont monitoring-01 comme hostname : ses requêtes ne doivent pas déclencher des alertes SQLi 


## Règles de corrélation multi-sources (LLM obligatoire)
-Kill Chain détection
Étape 1 : Port scan réseau depuis IP X (network, beaucoup de destination_port distincts)
Étape 2 : Auth failure depuis même IP X (authentication, status = failure)
Étape 3 : Auth success depuis IP X → compromission complète en 3 étapes
Le LLM corrèle les 3 étapes et reconstitue la timeline

-Exfiltration de données
bytes_sent anormalement élevé depuis db-prod-01 ou db-prod-02 vers IP externe
Combiné à un status_code = 200 sur URI de type /api/v1/export ou /api/v1/report

-Élévation de privilèges
log_source = system + severity = critical + process = auditd ou sudo
Suivi d'un auth_method = ssh success depuis la même machine peu après 
SANSA — Yesterday at 21:01


## Architecture de scoring des règles pour le LLM
Chaque log reçoit un score de risque cumulatif :

+10  IP dans un pays à 100% failure (CN, RU, KP, IR)
+20  > 50 auth failures depuis cette IP
+15  Path traversal / SQLi / SSRF détecté dans l'URI
+25  Impossible travel (même user, 2 pays < 1h)
+30  Kill chain complète (scan → failure → success)
+15  IP interne avec comportement d'attaquant externe
-10  IP whitelistée (monitoring-01, backup-01)
-5   user_agent légitime + IP connue

-Score > 40 → envoi au LLM pour analyse approfondie

-Score > 70 → soumission directe + LLM en parallèle

-L'enrichissement par threat intelligence Cyber Sierra (croiser les IPs suspectes avec des feeds comme AbuseIPDB ou Shodan) permettrait aussi d'augmenter la confiance sur des IPs comme 185.220.101.42 — qui est un nœud Tor connu — sans avoir besoin du LLM