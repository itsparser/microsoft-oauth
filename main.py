"""
    Created By  : itsparser
    Created On  : 03/03/22
"""
import logging
import os

import flask
import jwt
from flask import request

app = flask.Flask(__name__)

# Get the Secret from the environment Variable.
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")


# Disabling the ssl certificate check.
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

AZURE_OAUTH_REDIRECT_URL = "https://login.microsoftonline.com/common/oauth2/authorize?client_id={client_id}&" \
                           "response_type=code&redirect_uri={redirect_uri}&" \
                           "response_mode=query&state={state}"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/token"


@app.route("/")
def index():
    return """
    <a href="/login">Login</a>
    """


@app.route("/login")
def login():
    redirection_url = AZURE_OAUTH_REDIRECT_URL.format(
        client_id=CLIENT_ID, redirect_uri="http://localhost:5000/callback", state="http://localhost:5000/auth"
    )
    return flask.redirect(redirection_url)


@app.route("/callback")
def callback():
    import requests
    code = request.args.get("code")
    state = request.args.get('state')
    try:
        data = {'grant_type': 'authorization_code',
                'client_id': CLIENT_ID,
                'code': code,
                'redirect_uri': f"http://{request.host}{request.path}",
                'resource': 'https://management.core.windows.net/',
                'client_secret': CLIENT_SECRET}
        token_response = requests.post(TOKEN_URL, data=data)
        if token_response.status_code == 200:
            token = token_response.json()
            logging.info(f"Token: {token}")
            decoded_response = jwt.decode(token, options={"verify_signature": False})
            email = decoded_response['unique_name']
            return f"""
                User information: <br>
                Name: {decoded_response.get("name")} <br>
                Email: {decoded_response["unique_name"]} <br>
                Avatar <img src="{decoded_response.get('avatar_url')}"> <br>
                <a href="/">Home</a>
                """
            # return flask.redirect("{state}?email={email}&status=success".format(state=state, email=email))
        logging.error(f"Azure signin failed : {token_response.json()}")
    except Exception as err:
        logging.exception(err)
    return flask.redirect(f"{state}?status=failed")


if __name__ == '__main__':
    app.run(debug=True)
