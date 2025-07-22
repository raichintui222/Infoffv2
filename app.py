from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import base64
from datetime import datetime
import time
import my_pb2
import output_pb2

app = Flask(__name__)
SESSION = requests.Session()
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def log_info(message):
    print(f"[INFO] {message}")

def log_error(message):
    print(f"[ERROR] {message}")

def log_debug(message):
    print(f"[DEBUG] {message}")

def getGuestAccessToken(uid, password):
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    data = {
        "uid": str(uid),
        "password": str(password),
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = SESSION.post("https://100067.connect.garena.com/oauth/guest/token/grant",
                            headers=headers, data=data, verify=False)
    data_response = response.json()
    if data_response.get("success") is True:
        resp = data_response.get("response", {})
        if resp.get("error") == "auth_error":
            return {"error": "auth_error"}
    return {"access_token": data_response.get("access_token"), "open_id": data_response.get("open_id")}

def check_guest(uid, password):
    token_data = getGuestAccessToken(uid, password)
    if token_data.get("error") == "auth_error":
        return uid, None, None, True
    access_token = token_data.get("access_token")
    open_id = token_data.get("open_id")
    if access_token and open_id:
        log_debug(f"UID {uid}: Obtidos access_token e open_id via API")
        return uid, access_token, open_id, False
    log_error(f"UID {uid}: Falha no login, token ausente")
    return uid, None, None, False

def get_token_inspect_data(access_token):
    try:
        resp = SESSION.get(
            f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}",
            timeout=15,
            verify=False
        )
        data = resp.json()
        if 'open_id' in data and 'platform' in data and 'uid' in data:
            return data
    except Exception as e:
        log_error(f"Erro ao inspecionar token: {e}")
    return None

def login(uid, access_token, open_id, platform_type):
    log_debug(f"Iniciando login para UID {uid} com platform_type {platform_type}")
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    game_data = my_pb2.GameData()
    game_data.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    game_data.game_name = "Free Fire"
    game_data.game_version = 1
    game_data.version_code = "1.111.1"
    game_data.os_info = "iOS 18.4"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1170
    game_data.screen_height = 2532
    game_data.dpi = "460"
    game_data.cpu_info = "Apple A15 Bionic"
    game_data.total_ram = 6144
    game_data.gpu_name = "Apple GPU (5-core)"
    game_data.gpu_version = "Metal 3"
    game_data.user_id = uid
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = platform_type
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)
    serialized_data = game_data.SerializeToString()
    padded_data = pad(serialized_data, AES.block_size)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(padded_data)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB49",
        "Content-Length": str(len(encrypted_data))
    }
    try:
        response = SESSION.post(url, data=encrypted_data, headers=headers, timeout=30, verify=False)
        if response.status_code == 200:
            jwt_msg = output_pb2.Garena_420()
            jwt_msg.ParseFromString(response.content)
            if jwt_msg.token:
                log_debug(f"Login bem-sucedido para UID {uid}, token: {jwt_msg.token[:10]}...")
                return jwt_msg.token
        else:
            error_text = response.content.decode().strip()
            log_debug(f"API MajorLogin retornou status {response.status_code}: {error_text}")
            if error_text == "BR_PLATFORM_INVALID_PLATFORM":
                return {"error": "INVALID_PLATFORM", "message": "this account is registered on another platform"}
            elif error_text == "BR_GOP_TOKEN_AUTH_FAILED":
                return {"error": "INVALID_TOKEN", "message": "AccessToken invalid."}
            elif error_text == "BR_PLATFORM_INVALID_OPENID":
                return {"error": "INVALID_OPENID", "message": "OpenID invalid."}
    except Exception as e:
        log_error(f"UID {uid}: Erro na requisição de JWT - {e}")
    return None

@app.route("/api/get_jwt", methods=["GET"])
def get_jwt():
    guest_uid = request.args.get("guest_uid")
    guest_password = request.args.get("guest_password")
    if guest_uid and guest_password:
        uid, access_token, open_id, err_flag = check_guest(guest_uid, guest_password)
        if err_flag:
            return jsonify({
                "success": False,
                "message": "invalid guest_uid, guest_password"
            }), 400
        if not access_token or not open_id:
            return jsonify({
                "success": False,
                "message": "unregistered or banned account.",
                "detail": "jwt not found in response."
            }), 500
        jwt_token = login(uid, access_token, open_id, 4)
        if isinstance(jwt_token, dict):
            return jsonify(jwt_token), 400
        if not jwt_token:
            return jsonify({
                "success": False,
                "message": "unregistered or banned account.",
                "detail": "jwt not found in response."
            }), 500
        return jsonify({"success": True, "BearerAuth": jwt_token})

    access_token = request.args.get("access_token")
    if access_token:
        token_data = get_token_inspect_data(access_token)
        if not token_data:
            return jsonify({
                "error": "INVALID_TOKEN",
                "message": "AccessToken invalid."
            }), 400
        open_id = token_data["open_id"]
        platform_type = token_data["platform"]
        uid = str(token_data["uid"])
        jwt_token = login(uid, access_token, open_id, platform_type)
        if isinstance(jwt_token, dict):
            return jsonify(jwt_token), 400
        if not jwt_token:
            return jsonify({
                "success": False,
                "message": "unregistered or banned account.",
                "detail": "jwt not found in response."
            }), 500
        return jsonify({"success": True, "BearerAuth": jwt_token})

    return jsonify({
        "success": False,
        "message": "missing access_token (or guest_uid + guest_password)"
    }), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({"detail": "Not Found"}), 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    log_info(f"Iniciando o serviço na porta {port}")
    app.run(host="0.0.0.0", port=port)

