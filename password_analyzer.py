import math
import re
import hashlib
import requests

class PasswordAnalyzer:
    def __init__(self):
        # القائمة المحلية للكلمات البديهية
        self.common_passwords = {"12345678", "password", "123456", "password123", "admin", "qwerty"}

    def calculate_entropy(self, password):
        charset = 0
        if any(c.islower() for c in password): charset += 26
        if any(c.isupper() for c in password): charset += 26
        if any(c.isdigit() for c in password): charset += 10
        if any(not c.isalnum() for c in password): charset += 32

        if charset == 0:
            return 0
        
        return round(len(password) * math.log2(charset), 2)

    def has_sequences(self, password):
        password_lower = password.lower()
        for i in range(len(password) - 3):
            seq_num = "".join(chr(ord(password_lower[i]) + j) for j in range(4))
            if password_lower[i:i+4] == seq_num:
                return True
        return False

    def check_pwned(self, password):
        # تشفير كلمة المرور بـ SHA-1
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        # إرسال أول 5 رموز فقط للحفاظ على الخصوصية (k-Anonymity)
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        try:
            # مهلة 3 ثوانٍ حتى لا يتجمد البرنامج إذا انقطع الإنترنت
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return int(count) # عدد مرات تسريب هذه الكلمة
            return 0
        except requests.RequestException:
            # إذا فشل الاتصال، نعيد -1 لتجاهل الفحص عبر الإنترنت بدلاً من انهيار البرنامج
            return -1 

    def analyze(self, password):
        if not password:
            return {"status": "Waiting", "score": 0, "entropy": 0, "suggestions": []}

        # 1. فحص التسريبات العالمية (الأولوية القصوى)
        pwned_count = self.check_pwned(password)
        if pwned_count > 0:
            return {
                "status": "Compromised!",
                "score": 0.05,
                "entropy": 0,
                "suggestions": [f"CRITICAL DANGER: This password was leaked {pwned_count:,} times in global data breaches! Change it immediately."]
            }

        # 2. كشف كلمات المرور الشائعة محلياً
        if password.lower() in self.common_passwords:
            return {
                "status": "Very Weak",
                "score": 0.1,
                "entropy": 0,
                "suggestions": ["This is a very common password. Easily guessed!"]
            }

        suggestions = []
        
        if pwned_count == -1:
            suggestions.append("Note: Online breach check bypassed (No Internet connection).")

        # 3. الفحوصات التقليدية
        if len(password) < 8:
            suggestions.append("Use at least 8 characters")
        if not any(c.isupper() for c in password): 
            suggestions.append("Add uppercase letters")
        if not any(c.isdigit() for c in password): 
            suggestions.append("Add numbers")
        if not any(not c.isalnum() for c in password): 
            suggestions.append("Add special symbols")
            
        # 4. كشف التكرار والتسلسل
        if re.search(r"(.)\1{2,}", password): 
            suggestions.append("Avoid repeated characters")
        if self.has_sequences(password):
            suggestions.append("Avoid sequential characters (e.g., 1234, abcd)")

        entropy = self.calculate_entropy(password)
        
        # 5. حساب النتيجة النهائية
        if len(password) < 8:
            status = "Very Weak"
            score = 0.1
            entropy = 0
        elif len(suggestions) >= 3:
            status = "Weak"
            score = 0.3
        elif len(suggestions) == 2 or len(password) < 10:
            status = "Medium"
            score = 0.5
        elif len(suggestions) == 1 and pwned_count != -1:
            status = "Strong"
            score = 0.75
        else:
            status = "Very Strong"
            score = 1.0

        return {
            "status": status,
            "score": score,
            "entropy": entropy,
            "suggestions": suggestions
        }