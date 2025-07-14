hub:
  config:
    # JWT 토큰을 받기위해 필요한 암호화 키 설정
    CryptKeeper:
      keys:
        - ${crypt_keeper_key}
    # JWT 토큰을 받기위해 필요한 설정
    Authenticator:
      enable_auth_state: true
    JupyterHub:
      authenticator_class: "oauthenticator.generic.GenericOAuthenticator"
      admin_access: true
      admin_users:
        - management
    GenericOAuthenticator:
      client_id: "${client_id}"
      client_secret: "${client_secret}"
      oauth_callback_url: "${callback_url}"
      authorize_url: "${authorize_url}"
      token_url: "${token_url}"
      userdata_url: "${userdata_url}"
      scope:
        - openid
        - email
        - profile
      username_key: "preferred_username"
      userdata_params:
        state: state
      login_service: "Keycloak"
  extraConfig:
    my-config.py: |
      import jwt, time, json, urllib.request, os, base64
      async def pass_oidc_token(spawner):
          auth_state = await spawner.user.get_auth_state()
          if not auth_state:
              spawner.log.info("auth_state is None!")
              return
          id_token = auth_state.get('id_token')
          if id_token:
              try:
                  payload = jwt.decode(id_token, options={"verify_signature": False})
                  now = int(time.time())
                  if payload.get("exp", 0) < now:
                      spawner.log.error("OIDC token expired, forcing re-login")
                      from tornado import web
                      raise web.HTTPError(401, "OIDC token expired")
              except Exception as e:
                  spawner.log.error(f"Token decode error: {e}")
          # vault-test-jwt-login.py 에서 사용할 JWT Token을 여기서 입력 받는다.        
          spawner.environment['VAULT_OIDC_TOKEN'] = id_token

          # 1. Vault JWT 로그인 (POST /v1/auth/keycloak-jwt/login)
          vault_addr = "http://host.minikube.internal:8200"
          vault_role = "default"
          login_url = f"{vault_addr}/v1/auth/keycloak-jwt/login"
          login_data = json.dumps({
              "role": vault_role,
              "jwt": id_token
          }).encode("utf-8")
          req = urllib.request.Request(login_url, data=login_data, headers={"Content-Type": "application/json"})
          with urllib.request.urlopen(req) as resp:
              login_response = json.loads(resp.read().decode())
          client_token = login_response["auth"]["client_token"]

          # 2. Vault KV2 시크릿 읽기 (GET /v1/notebook-secret-kv-v2/data/test)
          secret_url = f"{vault_addr}/v1/notebook-secret-kv-v2/data/test"
          req2 = urllib.request.Request(secret_url, headers={"X-Vault-Token": client_token})
          with urllib.request.urlopen(req2) as resp2:
              secret_response = json.loads(resp2.read().decode())
          secret = secret_response['data']['data']['data']
          
          # 시크릿을 파일로 저장하고 환경변수로 전달
          try:
              secret_file_path = "/tmp/vault_secret_file.txt"
              with open(secret_file_path, "w", encoding='utf-8') as f:
                  f.write(str(secret))
              spawner.environment['VAULT_SECRET_FILE'] = secret_file_path
              spawner.environment['MY_SECRET'] = str(secret)
              spawner.log.info(f"Secret saved to: {secret_file_path}")
          except Exception as e:
              spawner.log.error(f"Error saving secret: {e}")
              spawner.environment['MY_SECRET'] = str(secret)
      c.KubeSpawner.pre_spawn_hook = pass_oidc_token
  db:
    type: sqlite-memory

singleuser:
  storage:
    type: none
  extraEnv:
    # .Values에서 Hub에서 전달받은 환경변수를 notebook 환경변수로 받아오기
    JUPYTER_ENABLE_LAB: "yes"
    MY_SECRET: "{{ .Values.singleuser.extraEnv.MY_SECRET | default \"\" }}"
    VAULT_SECRET_FILE: "{{ .Values.singleuser.extraEnv.VAULT_SECRET_FILE | default \"\" }}"
  lifecycleHooks:
    postStart:
      exec:
        command:
          - "sh"
          - "-c"
          - |
            pip install hvac PyJWT
            echo $MY_SECRET | base64 -d > $VAULT_SECRET_FILE

proxy:
  service:
    type: NodePort
    nodePorts:
      http: 30080
