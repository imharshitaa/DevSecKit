# STEPS TO RUN THE TEST SCANS

Clone this repository

```
git clone https://github.com/imharshitaa/DevSecKit.git
cd DevSecKit
```

Set up your environment

```
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
python3 -m venv venv
source venv/bin/activate
```

Install dependencies

```
pip install semgrep bandit safety pip-audit
```

Make scripts executable
```
chmod +x sast/run_sast.sh
chmod +x sca/run_sca.sh
```

Clone target repository
```
git clone https://github.com/psf/requests.git ~/requests
```

Run scans on a target repository
```
bash sast/run_sast.sh ~/requests
bash sca/run_sca.sh ~/requests
```
























