Devsec repo with sast sca codes: https://github.com/imharshitaa/DevSecKit.git 

Repo to scan test: https://github.com/psf/requests.git 

**Command to run:**

```
cd ~
git clone https://github.com/imharshitaa/DevSecKit.git
cd DevSecKit
```
```
chmod +x sast/run_sast.sh
chmod +x sca/run_sca.sh
```
```
sudo apt update && sudo apt install -y python3 python3-venv python3-pip docker.io git trivy
python3 -m venv ~/sast-venv
source ~/sast-venv/bin/activate
pip install semgrep bandit
docker pull owasp/dependency-check
```
```
git clone https://github.com/psf/requests.git ~/requests
```
```
bash sast/run_sast.sh ~/requests
```

<img width="999" height="492" alt="Screenshot 2025-10-10 164013" src="https://github.com/user-attachments/assets/9a88689f-3910-4718-baee-3884e04bfd1a" />


<img width="925" height="556" alt="Screenshot 2025-10-10 164047" src="https://github.com/user-attachments/assets/0560fe03-e434-4408-8ba7-a954672b7c4c" />


<img width="889" height="560" alt="Screenshot 2025-10-10 164114" src="https://github.com/user-attachments/assets/49987574-62aa-4572-ae9a-2a77415dfe97" />


<img width="765" height="381" alt="Screenshot 2025-10-10 164134" src="https://github.com/user-attachments/assets/f4f222fa-f9b6-45ad-99e0-d0ee5ae4b3f3" />


<img width="1283" height="669" alt="Screenshot 2025-10-10 164155" src="https://github.com/user-attachments/assets/56ab454b-670d-4c26-8c1d-2eee411a1f7c" />


<img width="1032" height="676" alt="Screenshot 2025-10-10 164223" src="https://github.com/user-attachments/assets/5d8c3026-7ec0-42e8-ad5f-2a81941b0684" />


<img width="463" height="322" alt="Screenshot 2025-10-10 164643" src="https://github.com/user-attachments/assets/5ff04e28-efd0-4f5a-a75d-4265ad5371cd" />































