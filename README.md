# Advanced Password Strength Analyzer (Cybersec Edition) 🛡️

A production-ready password analyzer built with Python and `customtkinter`. This project goes beyond basic regex checks by implementing real cybersecurity principles to evaluate password strength.

## 🚀 Key Features
- **Data Breach Detection:** Integrates with the *Have I Been Pwned* API to check if a password has been compromised in global data breaches.
- **Privacy First (k-Anonymity & SHA-1):** Ensures absolute user privacy by hashing the password locally and sending only the first 5 characters of the SHA-1 hash to the API.
- **Accurate Entropy Calculation:** Eliminates blind spots for predictable sequences (e.g., '12345678' is strictly evaluated as 0 bits of entropy).
- **Real-time UI:** Responsive and clean user interface with dynamic threat indicators based on the severity of vulnerabilities.

## 🛠️ Installation & Usage

1. Clone the repository:
```bash
git clone [https://github.com/Khaled-Aly-Elnagar/DecodeLabs-Internship.git](https://github.com/Khaled-Aly-Elnagar/DecodeLabs-Internship-p1.git)
Install required dependencies:

Bash
pip install customtkinter requests
Run the application:

Bash
python main.py
