#!/bin/bash

# apply existing migrations
python3 manage.py migrate

# make migrations for specific apps
apps=(
    "targetApp"
    "scanEngine"
    "startScan"
    "dashboard"
    "recon_note"
)

create_migrations() {
    local app=$1
    echo "Creating migrations for $app..."
    python3 manage.py makemigrations $app
    echo "Finished creating migrations for $app"
    echo "----------------------------------------"
}

echo "Starting migration creation process..."

for app in "${apps[@]}"
do
    create_migrations $app
done

echo "Migration creation process completed."

# apply migrations again
echo "Applying migrations..."
python3 manage.py migrate
echo "Migration process completed."


python3 manage.py collectstatic --no-input --clear

# Load default engines, keywords, and external tools
python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool

# install firefox https://askubuntu.com/a/1404401
echo '
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001

Package: firefox
Pin: version 1:1snap1-0ubuntu2
Pin-Priority: -1
' | tee /etc/apt/preferences.d/mozilla-firefox
apt update
apt install firefox -y

# Temporary fix for whatportis bug - See https://github.com/williamsouzadelima/suricatoos-scan/issues/984
sed -i 's/purge()/truncate()/g' /usr/local/lib/python3.10/dist-packages/whatportis/cli.py

# update whatportis
yes | whatportis --update

# clone dirsearch default wordlist
if [ ! -d "/usr/src/wordlist" ]
then
  echo "Making Wordlist directory"
  mkdir /usr/src/wordlist
fi

if [ ! -f "/usr/src/wordlist/" ]
then
  echo "Downloading Default Directory Bruteforce Wordlist"
  wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt
fi

# check if default wordlist for amass exists
if [ ! -f /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt ];
then
  echo "Downloading Deepmagic top 50000 Wordlist"
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt
fi

# clone Sublist3r
if [ ! -d "/usr/src/github/Sublist3r" ]
then
  echo "Cloning Sublist3r"
  git clone https://github.com/aboul3la/Sublist3r /usr/src/github/Sublist3r
fi
python3 -m pip install -r /usr/src/github/Sublist3r/requirements.txt

# clone OneForAll
if [ ! -d "/usr/src/github/OneForAll" ]
then
  echo "Cloning OneForAll"
  git clone https://github.com/shmilylty/OneForAll /usr/src/github/OneForAll
fi
python3 -m pip install -r /usr/src/github/OneForAll/requirements.txt

# clone eyewitness
if [ ! -d "/usr/src/github/EyeWitness" ]
then
  echo "Cloning EyeWitness"
  git clone https://github.com/FortyNorthSecurity/EyeWitness /usr/src/github/EyeWitness
  # pip install -r /usr/src/github/Eyewitness/requirements.txt
fi

# clone theHarvester (pinned: 4.x still ships requirements/base.txt + root theHarvester.py, runs on py3.10)
if [ ! -d "/usr/src/github/theHarvester" ]
then
  echo "Cloning theHarvester 4.4.4"
  git clone --branch 4.4.4 --depth 1 https://github.com/laramies/theHarvester /usr/src/github/theHarvester
fi
python3 -m pip install -r /usr/src/github/theHarvester/requirements/base.txt

# clone spiderfoot (pinned to a fixed release for reproducible OSINT parsing)
if [ ! -d "/usr/src/github/spiderfoot" ]
then
  echo "Cloning SpiderFoot v4.0"
  git clone --branch v4.0 --depth 1 https://github.com/smicallef/spiderfoot /usr/src/github/spiderfoot
fi
# SpiderFoot v4.0 pins pyyaml>=5.4.1,<6 but PyYAML 5.x has no py3.10 wheel and its sdist
# fails to build (AttributeError: cython_sources). 6.0.1 is already installed and works.
sed -i '/^[[:space:]]*pyyaml/Id' /usr/src/github/spiderfoot/requirements.txt
python3 -m pip install -r /usr/src/github/spiderfoot/requirements.txt

# clone vulscan
if [ ! -d "/usr/src/github/scipag_vulscan" ]
then
  echo "Cloning Nmap Vulscan script"
  git clone https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan
  echo "Symlinking to nmap script dir"
  ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan
  echo "Usage in Suricatoos, set vulscan/vulscan.nse in nmap_script scanEngine port_scan config parameter"
fi

# install h8mail
python3 -m pip install h8mail

# install gf patterns
if [ ! -d "/root/Gf-Patterns" ];
then
  echo "Installing GF Patterns"
  mkdir ~/.gf
  cp -r $GOPATH/src/github.com/tomnomnom/gf/examples/*.json ~/.gf
  git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
  mv ~/Gf-Patterns/*.json ~/.gf
fi

# store scan_results
if [ ! -d "/usr/src/scan_results" ]
then
  mkdir /usr/src/scan_results
fi

# test tools, required for configuration
naabu && subfinder && amass
nuclei

if [ ! -d "/root/nuclei-templates/geeknik_nuclei_templates" ];
then
  echo "Installing Geeknik Nuclei templates"
  git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/geeknik_nuclei_templates
else
  echo "Removing old Geeknik Nuclei templates and updating new one"
  rm -rf ~/nuclei-templates/geeknik_nuclei_templates
  git clone https://github.com/geeknik/the-nuclei-templates.git ~/nuclei-templates/geeknik_nuclei_templates
fi

if [ ! -f ~/nuclei-templates/ssrf_nagli.yaml ];
then
  echo "Downloading ssrf_nagli for Nuclei"
  wget https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O ~/nuclei-templates/ssrf_nagli.yaml
fi

if [ ! -d "/usr/src/github/CMSeeK" ]
then
  echo "Cloning CMSeeK"
  git clone https://github.com/Tuhinshubhra/CMSeeK /usr/src/github/CMSeeK
  pip install -r /usr/src/github/CMSeeK/requirements.txt
fi

# clone ctfr
if [ ! -d "/usr/src/github/ctfr" ]
then
  echo "Cloning CTFR"
  git clone https://github.com/UnaPibaGeek/ctfr /usr/src/github/ctfr
fi

# clone gooFuzz
if [ ! -d "/usr/src/github/goofuzz" ]
then
  echo "Cloning GooFuzz"
  git clone https://github.com/m3n0sd0n4ld/GooFuzz.git /usr/src/github/goofuzz
  chmod +x /usr/src/github/goofuzz/GooFuzz
fi

# httpx seems to have issue, use alias instead!!!
echo 'alias httpx="/go/bin/httpx"' >> ~/.bashrc

# TEMPORARY FIX, httpcore is causing issues with celery, removing it as temp fix
#python3 -m pip uninstall -y httpcore

# TEMPORARY FIX FOR langchain
pip install tenacity==8.2.2

loglevel='info'
if [ "$DEBUG" == "1" ]; then
    loglevel='debug'
fi

echo "Starting Celery Workers..."

commands=""

# Main scan worker
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/Suricatoos/\" -- celery -A Suricatoos.tasks worker --loglevel=$loglevel --optimization=fair --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &"$'\n'
else
    commands+="celery -A Suricatoos.tasks worker --loglevel=$loglevel --optimization=fair --autoscale=$MAX_CONCURRENCY,$MIN_CONCURRENCY -Q main_scan_queue &"$'\n'
fi

# API shared task worker
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/api/\" -- celery -A api.shared_api_tasks worker --pool=gevent --optimization=fair --concurrency=10 --loglevel=$loglevel -Q api_queue -n api_worker &"$'\n'
else
    commands+="celery -A api.shared_api_tasks worker --pool=gevent --concurrency=10 --optimization=fair --loglevel=$loglevel -Q api_queue -n api_worker &"$'\n'
fi

# Todas as filas leves/IO-bound sao servidas por UM unico worker gevent.
# Antes havia 1 processo por fila (21 processos), e cada worker Celery carrega
# o Django inteiro (~140MB RSS). Numa VM de 3.8GB isso esgotava a RAM no boot e
# causava swap thrashing -> load explodia e a maquina travava. Greenlets gevent
# sao baratos, entao um unico processo serve todas essas filas tranquilamente.
queues=(
    "initiate_scan_queue"
    "subscan_queue"
    "report_queue"
    "send_notif_queue"
    "send_task_notif_queue"
    "send_file_to_discord_queue"
    "send_hackerone_report_queue"
    "parse_nmap_results_queue"
    "nmap_queue"
    "geo_localize_queue"
    "query_whois_queue"
    "remove_duplicate_endpoints_queue"
    "run_command_queue"
    "query_reverse_whois_queue"
    "query_ip_history_queue"
    "llm_queue"
    "dorking_queue"
    "osint_discovery_queue"
    "h8mail_queue"
    "theHarvester_queue"
    "spiderfoot_queue"
    "send_scan_notif_queue"
    "hang_monitor_queue"
)
all_queues=$(IFS=,; echo "${queues[*]}")
# Concorrencia do worker gevent compartilhado. Greenlets sao baratos (o custo de
# RAM e o unico import do Django, NAO por-greenlet), entao da pra subir bastante
# em hosts maiores. Validado como inteiro porque entra no comando montado via
# eval logo abaixo; valor invalido/vazio cai no default seguro 50.
case "${SHARED_CONCURRENCY:-}" in
    ''|*[!0-9]*) shared_concurrency=50 ;;
    *)           shared_concurrency=$SHARED_CONCURRENCY ;;
esac

if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/Suricatoos/\" -- celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$shared_concurrency --loglevel=$loglevel -Q $all_queues -n shared_worker &"$'\n'
else
    commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$shared_concurrency --loglevel=$loglevel -Q $all_queues -n shared_worker &"$'\n'
fi

# Coordinator worker (gevent): serves coordinator_queue, where the fan-out
# orchestrators (vulnerability_scan, nuclei_scan) block on their group/chord
# barrier. On a PREFORK worker a blocked orchestrator holds a scarce process slot
# and can deadlock its own children (the multi-tenant scan-#28 hang). On gevent a
# blocked task is just a parked greenlet, so a high concurrency is essentially free
# and the orchestrators can never starve the heavy children running on the
# memory-bounded main_scan_queue. Keep this a SEPARATE worker from the shared IO
# worker so parked orchestrators never consume the IO worker's concurrency slots.
case "${COORDINATOR_CONCURRENCY:-}" in
    ''|*[!0-9]*) coordinator_concurrency=30 ;;
    *)           coordinator_concurrency=$COORDINATOR_CONCURRENCY ;;
esac
if [ "$DEBUG" == "1" ]; then
    commands+="watchmedo auto-restart --recursive --pattern=\"*.py\" --directory=\"/usr/src/app/Suricatoos/\" -- celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$coordinator_concurrency --loglevel=$loglevel -Q coordinator_queue -n coordinator_worker &"$'\n'
else
    commands+="celery -A Suricatoos.tasks worker --pool=gevent --optimization=fair --concurrency=$coordinator_concurrency --loglevel=$loglevel -Q coordinator_queue -n coordinator_worker &"$'\n'
fi
commands="${commands%&}"

eval "$commands"

wait