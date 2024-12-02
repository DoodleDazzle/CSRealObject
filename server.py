from flask import Flask, redirect, request, jsonify, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_cors import CORS
import requests
import os
from werkzeug.utils import secure_filename
from ibm_botocore.client import Config
import ibm_boto3
from config import APP_ID_CONFIG  # Ensure this file contains correct configuration
import logging
from ibm_botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# IBM Cloud Object Storage credentials
COS_API_KEY_ID = "09Pdtt_HTiP6_y-ivTW4x3w9EnbKviO_b1ipi3kdoXx_"
COS_ENDPOINT = "https://s3.us.cloud-object-storage.appdomain.cloud"  # Removed "/v2/endpoints"
COS_INSTANCE_CRN = "crn:v1:bluemix:public:cloud-object-storage:global:a/816004080f334097a854cb90d8101731:020a4a5f-4d8d-4bc4-972e-403f4d4c448a::"
BUCKET_NAME = "project-7"

# Initialize the COS client
cos_client = ibm_boto3.client(
    "s3",
    ibm_api_key_id=COS_API_KEY_ID,
    ibm_service_instance_id=COS_INSTANCE_CRN,
    config=Config(signature_version="oauth"),
    endpoint_url=COS_ENDPOINT  # Ensure this endpoint matches the bucket's region
)

app = Flask(__name__)
app.secret_key = '7ef46bb33e976716696f445cbd430af4'  # Replace with a secure key
CORS(app)  # Allow cross-origin requests

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, email):
        self.id = email
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

ALLOWED_EXTENSIONS = {
    'png', 'jpg', 'jpeg', 'gif', 'pdf',  # Existing types
    'js', 'zip', 'ppt', 'pptx', 'doc', 'docx',  # New document types
    'txt', 'csv', 'json', 'xml',  # Text and data formats
    'html', 'css', 'py', 'java', 'cpp', 'c', 'cs', 'rb', 'php',  # Coding file types
    'sql', 'md', 'yml', 'yaml', 'sh'  # Scripts and config files
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('secure_upload'))
    return "<a href='/auth/login'>Login with IBM App ID</a>"

@app.route('/auth/login')
def login():
    login_url = f"{APP_ID_CONFIG['oauthServerUrl']}/authorization" \
                f"?response_type=code&client_id={APP_ID_CONFIG['clientId']}" \
                f"&redirect_uri={APP_ID_CONFIG['redirectUri']}"
    return redirect(login_url)

@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({"error": "Authorization code not found"}), 400

    token_url = f"{APP_ID_CONFIG['oauthServerUrl']}/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": APP_ID_CONFIG['redirectUri'],
        "client_id": APP_ID_CONFIG['clientId'],
        "client_secret": APP_ID_CONFIG['secret'],
    }

    response = requests.post(token_url, headers=headers, data=payload)
    if response.status_code != 200:
        logging.error(f"Failed to get access token: {response.text}")
        return jsonify({"error": "Failed to get access token", "details": response.json()}), 400

    tokens = response.json()
    access_token = tokens.get('access_token')

    user_info_url = f"{APP_ID_CONFIG['oauthServerUrl']}/userinfo"
    headers = {"Authorization": f"Bearer {access_token}"}
    user_info_response = requests.get(user_info_url, headers=headers)

    if user_info_response.status_code != 200:
        logging.error(f"Failed to get user info: {user_info_response.text}")
        return jsonify({"error": "Failed to get user info", "details": user_info_response.json()}), 400

    user_info = user_info_response.json()
    user_email = user_info.get('email')

    if not user_email:
        return jsonify({"error": "Failed to retrieve user email"}), 400

    user = User(user_email)
    login_user(user)
    logging.info(f"User {user_email} logged in successfully.")

    return redirect(url_for('secure_upload'))

@app.route('/auth/logout')
@login_required
def logout():
    logout_user()
    logout_url = f"{APP_ID_CONFIG['oauthServerUrl']}/logout" \
                 f"?client_id={APP_ID_CONFIG['clientId']}" \
                 f"&redirect_uri=http://127.0.0.1:5000"
    return redirect(logout_url)

@app.route('/secure_upload', methods=['GET', 'POST'])
@login_required
def secure_upload():
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        
        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            try:
                # Upload file to COS
                cos_client.upload_fileobj(
                    uploaded_file.stream,
                    BUCKET_NAME,
                    filename
                )
                logging.info(f"File '{filename}' uploaded successfully to bucket '{BUCKET_NAME}'.")
                return jsonify({'message': 'File uploaded successfully!', 'filename': filename}), 200
            except ClientError as e:
                logging.error(f"Failed to upload to COS: {e}")
                return jsonify({'error': 'Failed to upload to COS', 'details': str(e)}), 500
        return jsonify({'error': 'Invalid or no file uploaded.'}), 400

    return render_template('secure_upload.html')

if __name__ == '__main__':
    app.run(debug=True)
