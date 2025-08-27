import os
import requests
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, JWTManager
)
from dotenv import load_dotenv

# =========================
# Configuração inicial
# =========================
load_dotenv()
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)

ZENDESK_DOMAIN = os.getenv("ZENDESK_SUBDOMAIN")  # ex: conecta.zendesk.com
ZENDESK_EMAIL = os.getenv("ZENDESK_EMAIL")
ZENDESK_TOKEN = os.getenv("ZENDESK_API_TOKEN")

# =========================
# Função auxiliar para chamar Zendesk
# =========================
def zendesk_request(method, endpoint, **kwargs):
    url = f"https://{ZENDESK_DOMAIN}{endpoint}"
    auth = (f"{ZENDESK_EMAIL}/token", ZENDESK_TOKEN)
    response = requests.request(method, url, auth=auth, **kwargs)
    return response

# =========================
# Rotas proxy para Zendesk
# =========================
@app.route("/api/community/posts/<int:post_id>", methods=["DELETE"])
@jwt_required()
def delete_post(post_id):
    r = zendesk_request("DELETE", f"/api/v2/community/posts/{post_id}")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code

@app.route("/api/help_center/users/<int:user_id>/user_subscriptions", methods=["GET"])
@jwt_required()
def user_subscriptions(user_id):
    r = zendesk_request("GET", f"/api/v2/help_center/users/{user_id}/user_subscriptions")
    return jsonify(r.json()), r.status_code

@app.route("/api/community/posts/<int:post_id>/comments", methods=["POST"])
@jwt_required()
def create_comment(post_id):
    data = request.get_json()
    r = zendesk_request("POST", f"/api/v2/community/posts/{post_id}/comments", json=data)
    return jsonify(r.json()), r.status_code

@app.route("/api/community/posts/<int:post_id>/votes", methods=["GET"])
@jwt_required()
def get_votes(post_id):
    r = zendesk_request("GET", f"/api/v2/community/posts/{post_id}/votes")
    return jsonify(r.json()), r.status_code

@app.route("/api/gather/badges", methods=["GET"])
@jwt_required()
def get_badges():
    r = zendesk_request("GET", "/api/v2/gather/badges")
    return jsonify(r.json()), r.status_code

@app.route("/api/search/users", methods=["GET"])
@jwt_required()
def search_users():
    query = "status_colaborador:ativo type:user"
    r = zendesk_request("GET", f"/api/v2/search.json?query={query}")
    return jsonify(r.json()), r.status_code

@app.route("/api/gather/badge_assignments", methods=["GET"])
@jwt_required()
def get_badge_assignments():
    user_id = request.args.get("user_id")
    r = zendesk_request("GET", f"/api/v2/gather/badge_assignments?user_id={user_id}")
    return jsonify(r.json()), r.status_code

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    data = request.get_json()
    r = zendesk_request("PUT", f"/api/v2/users/{user_id}.json", json=data)
    return jsonify(r.json()), r.status_code

@app.route("/api/help_center/votes/<int:vote_id>", methods=["DELETE"])
@jwt_required()
def delete_vote(vote_id):
    r = zendesk_request("DELETE", f"/api/v2/help_center/votes/{vote_id}")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code

@app.route("/api/community/posts/<int:post_id>/up", methods=["POST"])
@jwt_required()
def upvote_post(post_id):
    r = zendesk_request("POST", f"/api/v2/community/posts/{post_id}/up")
    return jsonify(r.json()), r.status_code

@app.route("/api/community/posts", methods=["GET"])
@jwt_required()
def get_post():
    r = zendesk_request("GET", "/api/v2/community/posts")
    return jsonify(r.json()), r.status_code

@app.route("/api/gather/badges/<int:badge_id>", methods=["GET"])
@jwt_required()
def get_badge(badge_id):
    r = zendesk_request("GET", f"/api/v2/gather/badges/{badge_id}")
    return jsonify(r.json()), r.status_code

@app.route("/api/user_fields/<int:field_id>", methods=["GET"])
@jwt_required()
def get_user_field(field_id):
    r = zendesk_request("GET", f"/api/v2/user_fields/{field_id}")
    return jsonify(r.json()), r.status_code

@app.route("/api/guide/user_images/uploads", methods=["POST"])
@jwt_required()
def upload_user_image():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "Arquivo não enviado"}), 400
    r = zendesk_request("POST", "/api/v2/guide/user_images/uploads", files={"file": file})
    return jsonify(r.json()), r.status_code

@app.route("/api/guide/user_images", methods=["POST"])
@jwt_required()
def create_user_image():
    data = request.get_json()
    r = zendesk_request("POST", "/api/v2/guide/user_images", json=data)
    return jsonify(r.json()), r.status_code

@app.route("/api/community/posts", methods=["POST"])
@jwt_required()
def create_post():
    data = request.get_json()
    r = zendesk_request("POST", "/api/v2/community/posts", json=data)
    return jsonify(r.json()), r.status_code

# =========================
# Autologin (gera JWT por e-mail/nome)
# =========================
@app.route("/autologin", methods=["GET"])
def autologin():
    email = request.args.get("email", "guest@zendesk.com")
    name = request.args.get("name", "Visitante")
    token = create_access_token(identity={"email": email, "name": name})
    return jsonify(access_token=token)

# Exemplo de rota protegida
@app.route("/me", methods=["GET"])
@jwt_required()
def me():
    user = get_jwt_identity()
    return jsonify(user=user)

# =========================
# Inicialização
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
