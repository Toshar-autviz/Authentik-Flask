from flask import Flask, redirect, url_for, session, request, make_response, render_template
import os
import requests

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# OAuth2 Configuration
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
token = os.getenv("TOKEN")


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email and password:
            res, error = flow_step(extract_query_string(), email, password)
            if error:
                return res
            else:
                return render_template('login.html', message='Invalid email or password.')
    return render_template('login.html', message='')


def extract_query_string():
    return "next=%2Fapplication%2Fo%2Fauthorize%2F%3Fresponse_type%3Dcode%26client_id%3DZZchoNSa9f8SVp8uqzWved5IF0Qaa62GNoGWDPBr%26redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A5000%252Fcallback%26scope%3Dopenid%2Bemail%2Bprofile"


def flow_step(url, email, password):
    base_url = 'http://localhost:9000/api/v3/flows/executor/default-authentication-flow/'
    params = {
        'query': f'{url}'
    }

    headers = {
        'authorization': f'Bearer {token}',
        'content-type': 'application/json',
    }

    # Define the common headers

    first_step = requests.get(base_url, params=params, headers=headers)
    headers1 = {
        "accept": "application/json",
        "authorization": f'Bearer {token}',
        "content-type": "application/json",
        "Cookie": f"authentik_session={first_step.cookies['authentik_session']}"

    }
    data = {
        "component": "ak-stage-identification",
        "uid_field": f"{email}",
        "password": f"{password}"
    }
    # print("here Second datata")
    base_url1 = f"http://localhost:9000/api/v3/flows/executor/default-authentication-flow/?query={url}"
    Third_Step = requests.post(base_url1, headers=headers1, json=data)
    fourth_step = requests.post(f"http://localhost:9000{Third_Step.json()['to']}", headers=headers1, json=data)

    headers1['Cookie'] = f"authentik_session={fourth_step.cookies['authentik_session']}"
    response = make_response(redirect(url_for('.profile')))
    response.set_cookie('authentik_session', f'{fourth_step.cookies["authentik_session"]}')
    session['authentik_session'] = fourth_step.cookies["authentik_session"]
    if fourth_step.json()['type'] == "redirect":
        return response, True
    else:
        return response, False


@app.route('/profile')
def profile():
    url = 'http://localhost:9000/api/v3/core/users/me/'
    headers = {
        'accept': 'application/json',
        'Cookie': f'authentik_session={session.get("authentik_session")}'
    }
    response = requests.get(url, headers=headers)
    return f'User info: {response.json()} <br> <a href="/logout">Logout</a>'


@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")


if __name__ == '__main__':
    app.run(debug=True)
