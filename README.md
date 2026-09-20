# -
스스로 백신을 만드는 봇
import os
from pathlib import Path
from typing import List, Dict
from sklearn.feature_extraction.text import TfidfVectorizer


class SelfStrengtheningAntivirus:
    """실제 파일 스캔 + 자기 학습 백신"""

    def __init__(self):
        self.rules_db = []
        self.vectorizer = TfidfVectorizer(max_features=30)
        self.feature_history = []
        self.version = 0

    def ai_analyze_malware(self, malware_samples: List[str]):
        """악성 샘플에서 핵심 특징 추출"""
        print("[AI] 악성 샘플 분석 중...")
        if not malware_samples:
            return []

        valid_samples = [s for s in malware_samples if isinstance(s, str) and s.strip()]
        if not valid_samples:
            return []

        self.vectorizer.fit(valid_samples)
        features = self.vectorizer.get_feature_names_out()
        self.feature_history.append(list(features))
        print(f"[AI] 추출된 핵심 악성 패턴: {list(features)}")
        return list(features)

    def auto_generate_code(self, version, features):
        """추출된 패턴으로 탐지 규칙 생성"""
        if not features:
            return None

        safe_features = [feat for feat in features if len(feat) >= 3]
        if not safe_features:
            safe_features = features[:5]

        rule_name = f"Detected_Malware_v{version}"
        strings_section = "\n        ".join([f'$str_{i} = "{feat}"' for i, feat in enumerate(safe_features)])

        yara_rule = f"""
rule {rule_name} {{
    meta:
        description = "AI가 자동 생성한 변종 악성코드 탐지 규칙"
        version = "{version}"
    strings:
        {strings_section}
    condition:
        any of them
}}
"""
        self.rules_db.append({
            "name": rule_name,
            "version": version,
            "patterns": [feat.lower() for feat in safe_features],
            "code": yara_rule
        })
        return yara_rule

    def scan_text(self, text: str) -> bool:
        """문자열 스캔: 규칙 패턴이 있으면 True"""
        if not text:
            return False

        lower_text = text.lower()
        for rule in self.rules_db:
            for keyword in rule["patterns"]:
                if keyword in lower_text:
                    return True
        return False

    def scan_file(self, file_path: str) -> bool:
        """단일 파일 검사"""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"[Scan] 파일 읽기 실패: {file_path} ({e})")
            return False

        # 바이너리를 텍스트처럼 다루기 위한 안전한 변환
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = str(data)

        return self.scan_text(text)

    def scan_directory(self, root_dir: str):
        """디렉터리 전체 재귀 스캔"""
        suspicious_files = []
        root = Path(root_dir)

        if not root.exists():
            print(f"[Scan] 경로 없음: {root_dir}")
            return suspicious_files

        for file_path in root.rglob("*"):
            if file_path.is_file():
                try:
                    flagged = self.scan_file(str(file_path))
                    if flagged:
                        suspicious_files.append(str(file_path))
                        print(f"🚨 [탐지] {file_path}")
                except Exception as e:
                    print(f"[Scan] 에러: {file_path} ({e})")

        if not suspicious_files:
            print("✅ [안전] 스캔된 파일 중 악성 파일 없음")
        return suspicious_files

    def collect_file_texts(self, folder: str):
        """폴더 내 파일 내용을 문자열 리스트로 수집"""
        texts = []
        folder_path = Path(folder)

        if not folder_path.exists():
            return texts

        for file_path in folder_path.rglob("*"):
            if file_path.is_file():
                try:
                    with open(file_path, "rb") as f:
                        data = f.read()
                    text = data.decode("utf-8", errors="ignore")
                    if text.strip():
                        texts.append(text)
                except Exception:
                    pass

        return texts

    def self_train(self, malicious_dir: str, benign_dir: str = None):
        """악성 폴더 학습 + 정상이미지/정상 파일 기반 오탐 방지"""
        malicious_samples = self.collect_file_texts(malicious_dir)
        features = self.ai_analyze_malware(malicious_samples)

        self.version += 1
        generated_rule = self.auto_generate_code(self.version, features)
        if generated_rule:
            print("\n🤖 [AI 생성 규칙]")
            print(generated_rule)

        if benign_dir:
            benign_samples = self.collect_file_texts(benign_dir)
            if benign_samples:
                safe_terms = set()
                for sample in benign_samples:
                    safe_terms.update(sample.lower().split())

                # 정상 파일에 등장하는 단어는 제외해서 오탐 줄이기
                final_features = [f for f in features if f.lower() not in safe_terms]
                if final_features:
                    self.version += 1
                    self.auto_generate_code(self.version, final_features)

        return generated_rule


# ==========================================
# 실사용 예시
# ==========================================
if __name__ == "__main__":
    antivirus = SelfStrengtheningAntivirus()

    # 예시: 악성 샘플 폴더
    # malware_dir = "./malware_samples"
    # benign_dir = "./safe_files"

    # 아래는 단순 데모용 샘플
    malware_samples = [
        "attack_server.com download ransomware encrypt_system",
        "ransomware encrypt_system bypass_av trojan_drop",
        "hidden_process encrypt_system attack_server.com"
    ]

    # 규칙 생성
    features = antivirus.ai_analyze_malware(malware_samples)
    rule = antivirus.auto_generate_code(version=1, features=features)
    print("\n[생성된 규칙]")
    print(rule)

    # 실제 파일 스캔 예시
    # 테스트 파일 생성
    test_dir = "./demo_files"
    os.makedirs(test_dir, exist_ok=True)

    suspicious_file = os.path.join(test_dir, "suspicious.txt")
    safe_file = os.path.join(test_dir, "safe.txt")

    with open(suspicious_file, "w", encoding="utf-8") as f:
        f.write("download attack_server.com encrypt_system ransomware payload")

    with open(safe_file, "w", encoding="utf-8") as f:
        f.write("hello world normal report document")

    print("\n[실제 파일 스캔 시작]")
    results = antivirus.scan_directory(test_dir)
    print(f"악성 파일 목록: {results}")
