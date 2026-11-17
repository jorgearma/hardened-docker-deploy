# Evidencias

Solo salidas **redactadas**. Las salidas en bruto van en `*/bruto/`, que está en `.gitignore` y nunca se sube.

Antes de cada commit:

```bash
gitleaks detect --no-git --source ofensivo/
grep -rnE '([0-9]{1,3}\.){3}[0-9]{1,3}' ofensivo/   # IPs olvidadas
```

Redactar: IPs, dominios, usuarios, rutas internas, nombres reconocibles de contenedores, tokens y versiones que sigan en uso.
