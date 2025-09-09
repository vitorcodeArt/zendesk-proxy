import os
import requests
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, JWTManager
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
CORS(app)  # Permite CORS de qualquer origem (para teste)

CORS(app, origins=["https://conecta.bcrcx.com"])


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
# Rotas proxy para Zendesk
# =========================

@app.route("/api/community/posts/<int:post_id>", methods=["DELETE"])
@jwt_required()
def delete_post(post_id):
    r = zendesk_request("DELETE", f"/api/v2/community/posts/{post_id}")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


@app.route("/api/community/posts/<int:post_id>/comments", methods=["POST"])
@jwt_required()
def create_comment(post_id):
    data = request.get_json()
    r = zendesk_request("POST", f"/api/v2/community/posts/{post_id}/comments", json=data)
    return jsonify(r.json()), r.status_code


@app.route("/api/community/posts/<int:post_id>/comments", methods=["GET"])
@jwt_required()
def get_comments(post_id):
    r = zendesk_request("GET", f"/api/v2/community/posts/{post_id}/comments.json")
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

@app.route("/api/gather/badge_assignments/user_id/<int:user_id>", methods=["GET"])
@jwt_required()
def get_badge_assignments(user_id):
    r = zendesk_request("GET", f"/api/v2/gather/badge_assignments?user_id={user_id}")
    return jsonify(r.json()), r.status_code



@app.route("/api/help_center/users/<int:user_id>/user_subscriptions/followings", methods=["GET"])
@jwt_required()
def user_subscriptions_followings(user_id):
    r = zendesk_request(
        "GET",
        f"/api/v2/help_center/users/{user_id}/user_subscriptions?type=followings"
    )
    return jsonify(r.json()), r.status_code


@app.route("/api/help_center/users/<int:user_id>/user_subscriptions/followers", methods=["GET"])
@jwt_required()
def user_subscriptions_followers(user_id):
    r = zendesk_request(
        "GET",
        f"/api/v2/help_center/users/{user_id}/user_subscriptions?type=followers"
    )
    return jsonify(r.json()), r.status_code

@app.route("/api/search/users", methods=["GET"])
@jwt_required()
def search_users():
    page = request.args.get("page", 1)
    per_page = request.args.get("per_page", 100)
    query = "status_colaborador:ativo type:user"

    zendesk_url = f"/api/v2/search.json?query={query}&page={page}&per_page={per_page}"
    r = zendesk_request("GET", zendesk_url)
    result_json = r.json()

    # Garantir que 'results' exista
    if "results" not in result_json:
        result_json["results"] = []

    # Ajuste do next_page para passar pelo proxy
    if result_json.get("next_page"):
        result_json["next_page"] = result_json["next_page"].replace(
            f"https://{ZENDESK_DOMAIN}", "https://zendesk-proxy-na06.onrender"
        )

    return jsonify(result_json), r.status_code



@app.route("/api/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):  # <- agora recebe direto do path
    r = zendesk_request("GET", f"/api/v2/users/{user_id}")
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
    data = request.get_json()

    # Verifica se veio o file_name
    if not data.get("file_name"):
        return jsonify({"error": "file_name é obrigatório"}), 400

    payload = {
        "file_name": data.get("file_name"),
        "content_type": data.get("content_type"),
        "file_size": data.get("file_size"),
    }

    r = zendesk_request("POST", "/api/v2/guide/user_images/uploads", json=payload)
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
# Inicialização
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Render define PORT
    app.run(host="0.0.0.0", port=port)