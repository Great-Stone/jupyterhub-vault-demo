import os, jwt, time, datetime, requests
import hvac

def get_latest_jwt():
    hub_api_url = "http://hub:8081/hub/user/token"
    api_token = os.environ.get("JUPYTERHUB_API_TOKEN")
    headers = {"Authorization": f"token {api_token}"}
    resp = requests.get(hub_api_url, headers=headers)
    if resp.status_code == 200:
        try:
            return resp.json().get("id_token")
        except Exception as e:
            print("❌ 응답을 JSON으로 파싱하지 못했습니다:", str(e))
            print("응답 내용:", resp.text)
            return None
    else:
        print(f"❌ 최신 JWT 토큰을 받아오지 못했습니다. (status: {resp.status_code})")
        print("응답 내용:", resp.text)
        return None

def check_and_use_jwt(token):
    payload = jwt.decode(token, options={"verify_signature": False})
    exp = payload.get("exp")
    now = int(time.time())
    remain = exp - now
    print("JWT 만료까지 남은 시간:", remain, "초")
    # 이미 만료
    if remain <= 0:
        print("❌ JWT 토큰이 만료되었습니다. JupyterHub에서 다시 로그인 후 서버를 재시작하세요.")
        from IPython.display import display, HTML
        display(HTML("""
            <div style="color:red;font-weight:bold;">
                ⚠️ JWT 토큰이 만료되었습니다.<br>
                <a href="/hub/home" target="_blank">여기를 클릭해 <b>노트북 서버(컨테이너)를 재시작</b>하세요!
            </div>
        """))
        return None
    # 10분 이하 남음
    elif remain <= 600:
        print("⚠️ JWT 토큰이 10분 이내로 곧 만료됩니다. 최신 토큰을 받아옵니다.")
        token_new = get_latest_jwt()
        if not token_new:
            print("재로그인 필요! JupyterHub에서 서버를 재시작하세요.")
            from IPython.display import display, HTML
            display(HTML("""
                <div style="color:red;font-weight:bold;">
                    ⚠️ JWT 토큰을 갱신할 수 없습니다.<br>
                    <a href="/hub/home" target="_blank">여기를 클릭해 <b>노트북 서버(컨테이너)를 재시작</b>하세요!
                </div>
            """))
            return None
        payload = jwt.decode(token_new, options={"verify_signature": False})
        print("최신 JWT payload:", payload)
        return token_new
    else:
        print("JWT 토큰이 충분히 남아 있습니다.")
        print("JWT payload:", payload)
        return token

token = os.environ.get("VAULT_OIDC_TOKEN")
token = check_and_use_jwt(token)
if not token:
    exit()  # 더 이상 진행하지 않음

print("JWT Token:", token[:30], "...")  # 토큰 일부만 출력

vault_addr = "http://host.minikube.internal:8200"
vault_role = "default"

client = hvac.Client(url=vault_addr)
login_response = client.auth.jwt.jwt_login(
    role=vault_role,
    jwt=token,
    path="keycloak-jwt"  # Vault에서 설정한 OIDC Auth Backend 경로
)

# Vault 클라이언트에 토큰 설정
client.token = login_response['auth']['client_token']
print("Vault client_token:", client.token)

# KV v2 시크릿 엔진에서 데이터 읽기
try:
    secret_response = client.secrets.kv.v2.read_secret_version(
        path='test',
        mount_point='notebook-secret-kv-v2',
        raise_on_deleted_version=True  # 경고 메시지 제거 
    )
    print("✅ 시크릿 데이터 조회 성공!")
    print("시크릿 데이터:", secret_response['data']['data'])
    print("메타데이터:")
    print("  - 생성 시간:", secret_response['data']['metadata']['created_time'])
    print("  - 버전:", secret_response['data']['metadata']['version'])
except Exception as e:
    print("❌ 시크릿 데이터 조회 실패:", str(e))
    print("현재 사용자가 management 권한을 가지고 있는지 확인하세요.")