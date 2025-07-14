# JupyterHub and Vault with OIDC authentication

이 저장소에는 Vault를 인증에 사용하는 JupyterHub 인스턴스의 구성 설정이 포함되어 있습니다.
Keycloak을 사용하여 인증 JupyterHub에 인증을 구현합니다.
JupyterHub에서 JWT 토큰을 사용하여 Vault에 인증을 구현합니다.

- Keycloak (Dev - tested 26.2.5)
- JupyterHub on Minikube (tested 1.36.0)
- Vault (Dev - tested 1.20.0)

## 1. 사전 실행 사항

### 1.1 Keycloak 실행

#### 다운로드

<https://www.keycloak.org/downloads>

#### 실행

실행을 위해서는 Java 21 이상이 설치된 환경이 권장됩니다. (Getting started - <https://www.keycloak.org/getting-started/getting-started-zip>)

압축 해제 후 `bin` 디렉토리에서 다음을 실행

```bash
export KC_BOOTSTRAP_ADMIN_USERNAME="admin"
export KC_BOOTSTRAP_ADMIN_PASSWORD="password"
./kc.sh start-dev
```

기본 주소 `http://localhost:8080` 에서 접속 후 관리자를 활성화

### 1.2 Vault Dev

#### 다운로드

<https://releases.hashicorp.com/vault/>

#### 실행

```bash
vault server -dev -dev-root-token-id=root
```

### 1.3 Minikube 실행

<https://minikube.sigs.k8s.io/docs/start/?arch=%2Fmacos%2Fx86-64%2Fstable%2Fbinary+download>

```bash
minikube start
```

```bash
127.0.0.1		host.minikube.internal
```

## 2. Terraform 실행

Terraform에서는 Keycloak에 클라이언트를 생성하고, JupyterHub 및 Vault에 대한 설정을 진행합니다.

```bash
cd terraform
terraform init
terraform apply
```

```bash
kubectl port-forward svc/proxy-public 30080:80 -n default
```

### 2.1 Terraform 구성 설명

테라폼에서는 Keycloak, Kubernetes(minikube), Vault에 대해 다음을 구성합니다.

#### Keycloak 설정
- **Realm 생성**: "HashiCorp" 라는 이름의 새로운 realm을 생성하고 토큰 수명을 1시간으로 설정
- **사용자 생성**: 
  - `reader` 사용자 (비밀번호: reader) - 읽기 권한만 가진 사용자
  - `management` 사용자 (비밀번호: management) - 관리 권한을 가진 사용자
- **역할(Role) 생성**:
  - `reader` 역할: 읽기 전용 권한
  - `management` 역할: 관리 권한 (reader 역할 포함)
- **OIDC 클라이언트 생성**: `vault-oidc` 클라이언트를 생성하여 Vault와 JupyterHub 인증 연동
- **프로토콜 매퍼 설정**: JWT 토큰에 사용자명, 역할 정보를 포함하도록 설정

#### Vault 설정
- **JWT 인증 백엔드 구성**:
  - `keycloak-oidc`: OIDC 방식 인증 (웹 UI용)
  - `keycloak-jwt`: JWT 방식 인증 (API/프로그래밍 방식용)
- **인증 역할 생성**: Keycloak의 사용자 정보와 역할을 Vault에 매핑
- **정책 및 그룹 설정**:
  - `reader` 그룹: `/secret/*` 경로에 대한 읽기 권한
  - `management` 그룹: `/secret/*` 경로에 대한 생성, 수정, 삭제 권한

#### JupyterHub 설정
- **Helm 차트 배포**: JupyterHub를 Kubernetes에 배포
- **OIDC 인증 연동**: Keycloak을 통한 Single Sign-On 설정
- **JWT 토큰 전달**: 사용자 환경변수로 OIDC 토큰을 전달하여 Vault 인증에 사용
- **토큰 서비스**: JWT 토큰을 갱신할 수 있는 내부 API 엔드포인트 제공

### 2.2 JupyterHub 설정 설명

JupyterHub는 Helm 차트를 통해 배포되며, `values.yaml.tpl` 파일에서 다음과 같은 주요 설정들이 구성됩니다:

#### Hub 설정
- **CryptKeeper**: 세션 암호화를 위한 키 설정
- **Authenticator 설정**:
  - `enable_auth_state: true`: 인증 상태 저장 활성화 (JWT 토큰 보관용)
  - `GenericOAuthenticator`: Keycloak OIDC 연동을 위한 OAuth 인증기 사용
  - 관리자 사용자로 `management` 계정 지정

#### OIDC 연동 설정
- **GenericOAuthenticator 구성**:
  - Keycloak의 클라이언트 ID/Secret 연동
  - OAuth 콜백 URL, 인증 URL, 토큰 URL, 사용자 정보 URL 설정
  - OpenID Connect 스코프 설정 (openid, email, profile)
  - 사용자명으로 `preferred_username` 필드 사용

#### 커스텀 설정 (extraConfig)
- **JWT 토큰 전달 로직** (`my-config.py`):
  - `pass_oidc_token` 함수: 사용자 스폰 시 JWT 토큰을 환경변수로 전달
  - JWT 토큰 만료 검증 및 만료 시 재로그인 강제
  - `VAULT_OIDC_TOKEN` 환경변수로 토큰 전달

- **JWT 토큰 서비스** (`jwt-token-service.py`):
  - `/hub/user/token` 엔드포인트 제공
  - 현재 사용자의 최신 JWT 토큰을 API로 제공
  - 토큰 갱신이 필요할 때 사용

#### 사용자 환경 설정
- **SingleUser 설정**:
  - 스토리지 비활성화 (임시 환경)
  - JupyterLab 활성화
  - 컨테이너 시작 시 필요한 Python 패키지 자동 설치 (`hvac`, `PyJWT`)

#### 네트워크 설정
- **Proxy 서비스**:
  - NodePort 타입으로 외부 접근 허용
  - 30080 포트로 서비스 노출


## 3. 테스트

1. 브라우저에서 `port-forward` 실행한 30080 포트에서 접속하여 JupyterHub에 접속합니다.

2. `Login with Keycloak` 을 클릭하여 Keycloak에 로그인합니다. (management 계정으로 로그인)

### 3.1 JupyterHub에서 OIDC 로그인 후 JWT 토큰 가져오기

`vault-test-jwt-login.py`의 내용을 붙여넣어 새로운 노트북을 실행합니다. 출력되는 내용의 예는 다음과 같습니다.

```log
JWT 만료까지 남은 시간: 2770 초
최신 JWT payload: {'exp': 1750983313, 'iat': 1750980439, 'auth_time': 1750979713, 'jti': '6c1b47c9-1243-4a4b-8908-a9c50674b56c', 'iss': 'http://host.minikube.internal:8080/realms/HashiCorp', 'aud': 'vault-oidc', 'sub': '251c182b-0399-4c54-8eb0-9cda7ed53b35', 'typ': 'ID', 'azp': 'vault-oidc', 'sid': '2f0e31c9-d988-489c-9c65-cee880208caf', 'at_hash': 'LJjyGxj6CAkat5zHiNF5lg', 'acr': '0', 'resource_access': {'vault-oidc': {'roles': ['management', 'reader']}}, 'email_verified': False, 'name': 'management top', 'preferred_username': 'management', 'given_name': 'management', 'family_name': 'top', 'email': 'management@domain.com', 'username': 'management'}
JWT payload: {'exp': 1750983313, 'iat': 1750980439, 'auth_time': 1750979713, 'jti': '6c1b47c9-1243-4a4b-8908-a9c50674b56c', 'iss': 'http://host.minikube.internal:8080/realms/HashiCorp', 'aud': 'vault-oidc', 'sub': '251c182b-0399-4c54-8eb0-9cda7ed53b35', 'typ': 'ID', 'azp': 'vault-oidc', 'sid': '2f0e31c9-d988-489c-9c65-cee880208caf', 'at_hash': 'LJjyGxj6CAkat5zHiNF5lg', 'acr': '0', 'resource_access': {'vault-oidc': {'roles': ['management', 'reader']}}, 'email_verified': False, 'name': 'management top', 'preferred_username': 'management', 'given_name': 'management', 'family_name': 'top', 'email': 'management@domain.com', 'username': 'management'}
현재 시각(now): 1750980543 2025-06-26 23:29:03
만료 시각(exp): 1750983313 2025-06-27 00:15:13
만료까지 남은 시간: 2770초 (46분 10초)
JWT Token: eyJhbGciOiJSUzI1NiIsInR5cCIgOi ...
Vault client_token: hvs.CAESILof7B_8Q5DC ...
```

`vault_token`을 사용하여 Vault에서 시크릿 데이터를 조회 합니다.

### 3.2 JupyterHub 설정으로 시크릿 데이터 가져오기

`vault-test-secret-from-extraconfig.py`의 내용을 붙여넣어 새로운 노트북을 실행합니다. 출력되는 내용의 예는 다음과 같습니다.

```log
dGhpcyBpcyBzZWNyZXQgZGF0YQ==
/tmp/vault_secret_file.txt
b'this is secret data'
```

- `jupyterhub`를 설치할 때 `OIDC` 구성됩니다.
- `hub.extraConfig`에서 `OIDC` 인증으로 받은 JWT Token으로 Vault에 JWT 방식으로 로그인 합니다.
- `hub.extraConfig`에서 Vault 인증 후 API로 필요한 시크릿을 가져와 환경변수에 넣습니다.
- `singleuser.extraEnv`에서 환경변수를 설정하여 사용자 환경에 전달합니다.
- `singleuser.lifecycleHooks.postStart.exec.command`에서 사용자 환경에 전달된 환경변수를 사용하여 시크릿을 파일로 저장합니다.

### 3.3 OIDC 로그인

`vault-test-oidc-login.py`의 내용을 붙여넣어 새로운 노트북을 실행합니다. 출력되는 내용의 예는 다음과 같습니다.

```log
브라우저에서 아래 URL로 이동해 로그인하세요:
http://127.0.0.1:8080/realms/HashiCorp/protocol/openid-connect/auth?client_id=vault-oidc&code_challenge=_BlnirYT7QYhEtr-pTlm1oEQdztApTArYCxIo5s0n1Q&code_challenge_method=S256&nonce=n_urNl3R3VX4GV7k8uEyL2&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob&response_type=code&scope=openid&state=st_xlbBDhcH7ZZYoM3kJ2XU
state 값(자동 추출): st_xlbBDhcH7ZZYoM3kJ2XU
브라우저에서 code 값을 입력하세요:  f878a4f9-47da-47c3-87ca-4d0e1639d3cc.017d0d38-5982-46e8-bdba-ced1277c3e84.aa2e252e-5717-4724-a3cf-aa8e5c1fc5e0

Vault 응답 상태코드: 200
Vault 시크릿: dGhpcyBpcyBzZWNyZXQgZGF0YQ==
b'this is secret data'
```

- `urn:ietf:wg:oauth:2.0:oob`를 사용하여 callback 요청을 하면 토큰을 받을 수 있습니다.
  - OOB는 "Out-Of-Band"의 약자입니다.
  - 웹서버를 띄울 수 없는 환경(예: CLI, 데스크탑 앱, 노트북 등)에서 OAuth/OIDC 인증을 할 때 사용합니다.
  - OOB 방식에서는 브라우저가 인증 코드를 직접 사용자에게 보여주고, 사용자가 그 코드를 복사해서 애플리케이션에 입력합니다.
- 애플리케이션이 인증 요청 시 redirect_uri로 "urn:ietf:wg:oauth:2.0:oob"를 지정합니다.
- 인증이 성공하면 브라우저 화면에 code(인증 코드)가 표시됩니다.
- 인증 코드를 사용하여 Vault에 인증을 요청합니다.





