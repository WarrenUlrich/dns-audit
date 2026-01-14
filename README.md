# dns-audit

Clone and init submodules:

```bash
git clone https://github.com/WarrenUlrich/dns-audit.git
cd dns-audit
git submodule update --init --recursive
```

Install required packages:

```bash
pip install -e lib/czds
pip install mysql-connector-python
```

## Environment Variables

Set the following before running:

```bash
export CZDS_USERNAME="your_czds_username"
export CZDS_PASSWORD="your_czds_password"

export MYSQL_HOST="db1"
export MYSQL_USER="nsaudit_user"
export MYSQL_PASSWORD="mysql_password"
export MYSQL_DATABASE="nsaudit"
```

## Run

```bash
python3 main.py
```

---
