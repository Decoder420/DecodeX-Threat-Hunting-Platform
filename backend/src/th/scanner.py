import yara
import os
import glob

RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

class YaraScanner:
    def __init__(self):
        self.rules = None
        self.reload_rules()

    def reload_rules(self):
        rule_files = glob.glob(os.path.join(RULES_DIR, "*.yar"))
        if not rule_files: return
        try:
            filepaths = {f"rule_{i}": path for i, path in enumerate(rule_files)}
            self.rules = yara.compile(filepaths=filepaths)
            print(f"[OK] YARA Engine: Compiled {len(rule_files)} rules.")
        except Exception as e:
            print(f"[ERROR] YARA Error: {e}")

    def scan_log(self, log_data):
        if not self.rules:
            return []
        try:
            # Enforce max payload inspection size (64KB) and match timeout (3s) for safety
            data_str = str(log_data)[:65536]
            matches = self.rules.match(data=data_str, timeout=3)
            return [m.rule for m in matches]
        except Exception as e:
            return []

scanner = YaraScanner()