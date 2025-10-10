
Devsec repo with sast sca codes: https://github.com/imharshitaa/DevSecKit.git

Repo to scan test: https://github.com/psf/requests.git

**Command to run:**

```
cd ~
git clone https://github.com/imharshitaa/DevSecKit.git
cd DevSecKit
```
```
chmod +x sca/run_sca.sh
```
```
sudo apt update && sudo apt install -y python3 python3-venv 
python3 -m venv ~/sast-venv
source ~/sast-venv/bin/activate
```
```
pip install safety pip-audit
```
```
git clone https://github.com/psf/requests.git ~/requests
```
```
bash sca/run_sca.sh ~/requests
```

<img width="435" height="176" alt="Screenshot 2025-10-10 174843" src="https://github.com/user-attachments/assets/8e831931-f1ba-41d3-83fc-e70b20a2a9c8" />











