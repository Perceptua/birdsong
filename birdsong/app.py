from birdsong.passbird import Passbird
from flask import Flask, redirect, request, session, url_for
import os


app = Flask(__name__)
app.secret_key = os.urandom(50)
passbird = Passbird('perceptua-twitter', 'http://localhost:5000/auth')
passbird.authorize()


@app.route('/')
def home():
    session['oauth_state'] = passbird.state

    return redirect(passbird.auth_url)

@app.route('/auth', methods=['GET'])
def callback():
    code = request.args.get('code')

    response = passbird.oauth_session.fetch_token(
        token_url=passbird.token_url,
        client_secret=passbird.client_secret,
        code_verifier=passbird.code_verifier,
        code=code
    )

    passbird.access_token = response['access_token']

    return redirect(url_for('user'))

@app.route('/user')
def user():
    user = passbird.get_user()
    username = user['data']['username']

    return redirect(url_for('user_tweets', username=username))

@app.route('/<username>/tweets')
def user_tweets(username):
    tweets = passbird.get_user_tweets(username)

    return tweets