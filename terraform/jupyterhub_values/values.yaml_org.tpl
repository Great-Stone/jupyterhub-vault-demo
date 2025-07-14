hub:
  config:
    CryptKeeper:
      keys:
        - "c_Xob_CjEzdOpBy0u8waG3QTmkSAXx3ncq7BDwwXZiQ="
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
      import jwt, time, hvac
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
          spawner.environment['VAULT_OIDC_TOKEN'] = id_token
      c.KubeSpawner.pre_spawn_hook = pass_oidc_token
    jwt-token-service.py: |
      from jupyterhub.services.auth import HubAuthenticated
      from tornado import web
      import json

      class TokenHandler(HubAuthenticated, web.RequestHandler):
          async def get(self):
              user = await self.get_current_user()
              auth_state = await user.get_auth_state()
              id_token = auth_state.get('id_token')
              self.finish(json.dumps({'id_token': id_token}))

      def setup_handlers(web_app):
          base_url = web_app.settings['base_url']
          route_pattern = base_url + 'user/token'
          handlers = [(route_pattern, TokenHandler)]
          web_app.add_handlers('.*$', handlers)
  db:
    type: sqlite-memory

singleuser:
  storage:
    type: none
  extraEnv:
    JUPYTER_ENABLE_LAB: "yes"
  lifecycleHooks:
    postStart:
      exec:
        command:
          - "sh"
          - "-c"
          - "pip install hvac PyJWT"

proxy:
  service:
    type: NodePort
    nodePorts:
      http: 30080
