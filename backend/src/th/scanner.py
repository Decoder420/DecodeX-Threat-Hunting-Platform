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
        if not self.rules: return []
        matches = self.rules.match(data=str(log_data))
        return [m.rule for m in matches]

scanner = YaraScanner()