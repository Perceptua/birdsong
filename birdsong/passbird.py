from requests_oauthlib import OAuth2Session
import base64
import hashlib
import json
import os
import re
import requests


class Passbird:
    def __init__(self, app_name: str, redirect_uri: str):
        self.app_name = app_name
        self.redirect_uri = redirect_uri
        self.api_key = os.environ['TWITTER_API_KEY']
        self.api_secret = os.environ['TWITTER_API_SECRET']
        self.client_id = os.environ['TWITTER_CLIENT_ID']
        self.client_secret = os.environ['TWITTER_CLIENT_SECRET']
        self.base_url = 'https://api.twitter.com'
        self.auth_url = 'https://twitter.com/i/oauth2/authorize'
        self.token_url = 'https://api.twitter.com/2/oauth2/token'
        self.oauth_session = None
        self.code_verifier = None
        self.code_challenge = None
        self.challenge_method = None
        self.state = None
        self.access_token = None

        self.scopes = [
            'tweet.read', 
            'users.read', 
            'like.read', 
            'offline.access'
        ]

    def make_code_verifier(self):
        code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode('utf-8')
        code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

        return code_verifier
    
    def make_code_challenge(self, code_verifier: str):
        method = 'S256'
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()

        code_challenge = base64.urlsafe_b64encode(
            code_challenge
        ).decode('utf-8')

        code_challenge = code_challenge.replace('=', '')

        return code_challenge, method
    
    def make_oauth_session(self):
        oauth_session = OAuth2Session(
            self.client_id, 
            redirect_uri=self.redirect_uri, 
            scope=self.scopes
        )

        return oauth_session
    
    def set_auth_state(
            self, oauth_session: OAuth2Session, code_challenge: str, method: str
        ):
        authorization_url, state = oauth_session.authorization_url(
            self.auth_url, 
            code_challenge=code_challenge, 
            code_challenge_method=method
        )

        return authorization_url, state
        
    def authorize(self):
        self.oauth_session = self.make_oauth_session()
        self.code_verifier = self.make_code_verifier()

        self.code_challenge, self.challenge_method = self.make_code_challenge(
            self.code_verifier
        )

        self.auth_url, self.state = self.set_auth_state(
            self.oauth_session, self.code_challenge, self.challenge_method
        )

        return self.oauth_session, self.auth_url, self.state
    
    def parse_response(self, response):
        if 200 <= response.status_code < 300:
            parsed = json.loads(response.text)
        else:
            parsed = {
                'status_code': response.status_code,
                'reason': response.reason
            }

        return parsed
    
    def get_default_headers(self):
        '''
        Get default headers for API requests.

        Parameters
        ----------
        None.

        Returns
        -------
        headers : dict(str, str)
            Dictionary of default request headers
        '''
        headers = {
            'Host': 'api.twitter.com',
            'User-Agent': self.app_name,
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        }

        return headers
    
    def get_bearer_token(self):
        '''
        Get Bearer access token from the oauth2/token endpoint.

        Basic authentication is used to get the Bearer access token. Client 
        ID & secret are encoded & passed to the oauth2/token endpoint in the 
        request Authorization header.

        Returns
        -------
        bearer_token : dict(str, str)
            Dictionary of Bearer access token information.
        '''
        auth_token = base64.b64encode(
            f'{self.api_key}:{self.api_secret}'.encode('utf-8')
        ).decode("ascii")

        headers = self.get_default_headers()
        headers['Authorization'] = f'Basic {auth_token}'
        data=b'grant_type=client_credentials'
        url = f'{self.base_url}/oauth2/token'
        resp = requests.post(url, headers=headers, data=data)
        bearer_token = self.parse_response(resp)

        return bearer_token
    
    def get_user(self):
        url = f'{self.base_url}/2/users/me'
        headers = self.get_default_headers()
        headers['Authorization'] = f'Bearer {self.access_token}'
        resp = requests.get(url, headers=headers)
        user = self.parse_response(resp)

        return user
    
    def get_user_tweets(self, username):
        url = f'{self.base_url}/2/tweets/search/all'
        token = self.get_bearer_token()['access_token']
        headers = self.get_default_headers()
        headers['Authorization'] = f'Bearer {token}'
        params={'query': f'from:{username}'}
        resp = requests.get(url, headers=headers, params=params)
        user_tweets = self.parse_response(resp)

        return user_tweets