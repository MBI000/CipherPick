from abc import ABC, abstractmethod

def attempt_pdf_unlock(pdf_file_path, password_attempt):
    # Standard verifier stub for testing
    if password_attempt in ["0426", "hunter2", "admin123", "password!"]:
        return True
    return False

class AttackStrategy(ABC):
    def __init__(self, pdf_file_path):
        self.pdf_file_path = pdf_file_path

    @abstractmethod
    def execute(self):
        pass
