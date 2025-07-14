import requests
import urllib.parse
import hvac
import base64

VAULT_ADDR = "http://host.minikube.internal:8200"
OIDC_PATH = "keycloak-oidc"
REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"

# 1. auth_url 요청 (role 명시)
resp = requests.post(
    f"{VAULT_ADDR}/v1/auth/{OIDC_PATH}/oidc/auth_url",
    json={
        "redirect_uri": REDIRECT_URI,
        "role": "default"
    }
)
auth_url = resp.json()["data"]["auth_url"]
print("브라우저에서 아래 URL로 이동해 로그인하세요:")
print(auth_url)

# 2. auth_url에서 state 파라미터 추출
parsed = urllib.parse.urlparse(auth_url)
query = urllib.parse.parse_qs(parsed.query)
state = query["state"][0]
print("state 값(자동 추출):", state)

# 3. 브라우저에서 code만 복사
code = input("브라우저에서 code 값을 입력하세요: ")

# 4. Vault에 callback 요청 (GET)
params = {
    "code": code,
    "state": state,
    "redirect_uri": REDIRECT_URI
}
resp2 = requests.get(
    f"{VAULT_ADDR}/v1/auth/{OIDC_PATH}/oidc/callback",
    params=params
)
print("Vault 응답 상태코드:", resp2.status_code)
# print("Vault 응답 본문:", resp2.text)
try:
    result = resp2.json()
    client_token = result["auth"]["client_token"]

    # hvac 클라이언트로 Vault API 사용
    client = hvac.Client(url=VAULT_ADDR, token=client_token)
    # 예시: KV v2 시크릿 읽기
    secret = client.secrets.kv.v2.read_secret_version(
        path="test",
        mount_point="notebook-secret-kv-v2",
        raise_on_deleted_version=True
    )
    print("Vault 시크릿:", secret["data"]["data"]["data"])

    # 파일로 저장
    with open("vault_secret.txt", "w") as f:
        f.write(base64.b64decode(secret["data"]["data"]["data"]).decode("utf-8"))

    with open("vault_secret.txt", "rb") as f:
        file_content = f.read()
        print("파일 내용")
        print(file_content)

except Exception as e:
    print("JSON 파싱 에러:", e)