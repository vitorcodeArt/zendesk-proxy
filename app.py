import os
import requests
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    create_access_token, jwt_required, JWTManager
)
from flask_cors import CORS
from dotenv import load_dotenv

# =========================
# Configuração inicial
# =========================
load_dotenv()
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)
CORS(app)

ZENDESK_DOMAIN = os.getenv("ZENDESK_SUBDOMAIN")
ZENDESK_EMAIL = os.getenv("ZENDESK_EMAIL")
ZENDESK_TOKEN = os.getenv("ZENDESK_API_TOKEN")

# =========================
# LOGIN (gera JWT para testar)
# =========================
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if data.get("username") == "admin" and data.get("password") == "123":
        token = create_access_token(identity="admin")
        return jsonify(access_token=token)
    return jsonify({"msg": "Credenciais inválidas"}), 401

# =========================
# Função auxiliar para chamar Zendesk
# =========================
def zendesk_request(method, endpoint, **kwargs):
    url = f"https://{ZENDESK_DOMAIN}.com{endpoint}"
    auth = (f"{ZENDESK_EMAIL}/token", ZENDESK_TOKEN)
    response = requests.request(method, url, auth=auth, **kwargs)
    return response

# =========================
# Função genérica de paginação
# =========================
def zendesk_paginated_request(endpoint, page=None, per_page=25):
    params = {}
    if page:
        params["page"] = page
    params["per_page"] = per_page

    r = zendesk_request("GET", endpoint, params=params)
    data = r.json()

    # Substitui next_page para apontar para o proxy
    if "next_page" in data and data["next_page"]:
        data["next_page"] = f"{request.path}?page={page+1 if page else 2}&per_page={per_page}"

    return data, r.status_code

# =========================
# Rotas paginadas
# =========================
@app.route("/api/search/users", methods=["GET"])
@jwt_required()
def search_users():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 25))
    query = "status_colaborador:ativo type:user"
    data, status = zendesk_paginated_request(f"/api/v2/search.json?query={query}", page, per_page)
    return jsonify(data), status

@app.route("/api/community/posts", methods=["GET"])
@jwt_required()
def get_posts():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 25))
    data, status = zendesk_paginated_request("/api/v2/community/posts", page, per_page)
    return jsonify(data), status

@app.route("/api/help_center/users/<int:user_id>/user_subscriptions", methods=["GET"])
@jwt_required()
def user_subscriptions(user_id):
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 25))
    type_sub = request.args.get("type", "followers")
    data, status = zendesk_paginated_request(
        f"/api/v2/help_center/users/{user_id}/user_subscriptions?type={type_sub}", page, per_page
    )
    return jsonify(data), status

# =========================
# Rotas padrão sem paginação
# =========================
@app.route("/api/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    r = zendesk_request("GET", f"/api/v2/users/{user_id}")
    return jsonify(r.json()), r.status_code

@app.route("/api/gather/badges", methods=["GET"])
@jwt_required()
def get_badges():
    r = zendesk_request("GET", "/api/v2/gather/badges")
    return jsonify(r.json()), r.status_code

@app.route("/api/gather/badges/<int:badge_id>", methods=["GET"])
@jwt_required()
def get_badge(badge_id):
    r = zendesk_request("GET", f"/api/v2/gather/badges/{badge_id}")
    return jsonify(r.json()), r.status_code

@app.route("/api/gather/badge_assignments", methods=["GET"])
@jwt_required()
def get_badge_assignments():
    user_id = request.args.get("user_id")
    r = zendesk_request("GET", f"/api/v2/gather/badge_assignments?user_id={user_id}")
    return jsonify(r.json()), r.status_code

# Outras rotas CRUD padrão permanecem iguais
# Exemplo: criar posts, comentários, upvotes, upload de imagens, etc.


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


@app.route("/api/community/posts/<int:post_id>/comments", methods=["POST"])
@jwt_required()
def create_comment(post_id):
    data = request.get_json()
    r = zendesk_request("POST", f"/api/v2/community/posts/{post_id}/comments", json=data)
    return jsonify(r.json()), r.status_code


@app.route("/api/community/posts/<int:post_id>", methods=["DELETE"])
@jwt_required()
def delete_post(post_id):
    r = zendesk_request("DELETE", f"/api/v2/community/posts/{post_id}")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code

# =========================
# Inicialização
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
