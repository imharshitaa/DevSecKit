# STEPS TO RUN THE TEST SCANS

Install Tools on Terminal

```bash
# 1. Update system
sudo apt update && sudo apt install -y python3 python3-venv python3-pip docker.io git

# 2. Setup Python virtual environment
python3 -m venv ~/sast-venv
source ~/sast-venv/bin/activate

# 3. Install SAST tools
pip install semgrep bandit

# 4. Install SCA tools
sudo apt install -y trivy
docker pull owasp/dependency-check
```

SAST setup

```bash
bash sast/run_sast.sh /path/to/target-repo
```

SCA Setup

```bash
bash sca/run_sca.sh /path/to/target-repo
```

Running on TERMINAL
-

1. Clone your target project
```
git clone https://github.com/example/target-repo.git ~/target-repo
```

2. Activate Python venv for SAST:
```
source ~/sast-venv/bin/activate
```

3. Run SAST scan
```
bash ~/security-scanner/sast/run_sast.sh ~/target-repo
```

4. Run SCA scan
```
bash ~/security-scanner/sca/run_sca.sh ~/target-repo
```























