import os

secret = os.environ.get("MY_SECRET")
print(secret)

file_path = os.environ.get("VAULT_SECRET_FILE")
print(file_path)

with open(file_path, "rb") as file:
    file_content = file.read()
    print(file_content)  # 출력 시 주의: 바이너리 데이터이므로 이진값이 출력됨