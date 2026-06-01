import customtkinter as ctk
from password_analyzer import PasswordAnalyzer

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class PasswordCheckerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.analyzer = PasswordAnalyzer()

        self.title("Advanced Password Checker (Cybersec Edition)")
        self.geometry("650x550")
        self.resizable(False, False)

        self.label = ctk.CTkLabel(
            self,
            text="Advanced Password Checker",
            font=("Arial", 24, "bold")
        )
        self.label.pack(pady=20)

        self.password_var = ctk.StringVar()
        self.password_entry = ctk.CTkEntry(
            self,
            width=400,
            show="*",
            placeholder_text="Enter Password",
            textvariable=self.password_var
        )
        self.password_entry.pack(pady=10)

        self.password_var.trace_add("write", lambda *args: self.analyze_password())

        self.show_password = ctk.CTkCheckBox(
            self,
            text="Show Password",
            command=self.toggle_password
        )
        self.show_password.pack(pady=5)

        self.result_label = ctk.CTkLabel(
            self,
            text="Waiting for input...",
            font=("Arial", 16)
        )
        self.result_label.pack(pady=10)

        self.progress = ctk.CTkProgressBar(
            self,
            width=400
        )
        self.progress.pack(pady=10)
        self.progress.set(0)

        self.length_label = ctk.CTkLabel(
            self,
            text="Length: 0"
        )
        self.length_label.pack()

        self.entropy_label = ctk.CTkLabel(
            self,
            text="Entropy: 0 bits"
        )
        self.entropy_label.pack(pady=5)

        self.suggestions_box = ctk.CTkTextbox(
            self,
            width=500,
            height=180
        )
        self.suggestions_box.pack(pady=20)

    def toggle_password(self):
        if self.show_password.get() == 1:
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def analyze_password(self):
        password = self.password_entry.get()

        if not password:
            self.result_label.configure(text="Waiting for input...")
            self.progress.set(0)
            self.length_label.configure(text="Length: 0")
            self.entropy_label.configure(text="Entropy: 0 bits")
            self.suggestions_box.delete("1.0", "end")
            return

        self.length_label.configure(text=f"Length: {len(password)}")

        # ملاحظة: استدعاء الـ API قد يسبب تأخيراً أجزاء من الثانية في الواجهة (Blocking)
        # في المشاريع الضخمة يتم معالجته بـ Threading، لكن لهذا النطاق هو مقبول جداً
        result = self.analyzer.analyze(password)

        self.result_label.configure(text=f"Status: {result['status']}")
        self.progress.set(result["score"])

        color_mapping = {
            "Compromised!": "#8B0000", # أحمر داكن
            "Very Weak": "red",
            "Weak": "#B22222",
            "Medium": "orange",
            "Strong": "light green",
            "Very Strong": "green"
        }
        
        current_color = color_mapping.get(result["status"], "blue")
        self.progress.configure(progress_color=current_color)
        self.entropy_label.configure(text=f"Entropy: {result['entropy']} bits")

        self.suggestions_box.delete("1.0", "end")

        if result["suggestions"]:
            for item in result["suggestions"]:
                self.suggestions_box.insert("end", f"• {item}\n")
        else:
            self.suggestions_box.insert("end", "Excellent, Uncompromised Password!")


if __name__ == "__main__":
    app = PasswordCheckerApp()
    app.mainloop()