import os
import requests

from flask import make_response
from flask import Flask, jsonify, request
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, JWTManager
)
from flask_cors import CORS
from dotenv import load_dotenv
from urllib.parse import urlparse, parse_qs, urlencode


# =========================
# Configuração inicial
# =========================
load_dotenv()
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
jwt = JWTManager(app)
CORS(app)  # Permite CORS de qualquer origem (para teste)

# Origens permitidas para o proxy
ALLOWED_ORIGINS = {
    "https://conecta.bcrcx.com",
    "https://institucional.bcrcx.com",
}

CORS(
    app,
    resources={r"/api/*": {"origins": list(ALLOWED_ORIGINS)}},
    supports_credentials=True,
)

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

@app.route("/api/gather/votes", methods=["GET"])
@jwt_required()
def get_all_votes():
    try:
        all_votes = []
        url = "/api/v2/help_center/votes"

        while url:
            r = zendesk_request("GET", url)
            data = r.json()

            if "votes" in data:
                all_votes.extend(data["votes"])
            else:
                break

            # Tratar paginação
            url = data.get("next_page")
            if url and url.startswith("https://"):
                url = url.replace("https://conecta.bcrcx.com", "")

        return jsonify({"votes": all_votes}), 200

    except Exception as e:
        print(f"Erro ao buscar votes: {e}")
        return jsonify({"error": "Falha ao buscar votos"}), 502



@app.route("/api/gather/badges", methods=["GET"])
@jwt_required()
def get_badges():
    r = zendesk_request("GET", "/api/v2/gather/badges")
    return jsonify(r.json()), r.status_code

@app.route("/api/gather/badge_assignments/user_id/<int:user_id>",methods=["GET"])
@jwt_required()
def get_badge_assignments(user_id):
    try:
        r = zendesk_request("GET", f"/api/v2/gather/badge_assignments?user_id={user_id}")
        data = r.json()
        return jsonify(data), r.status_code
    except Exception as e:
        print(f"Erro ao buscar badge_assignments: {e}")
        return jsonify({"error": "Falha ao buscar badges"}), 502

@app.route("/api/gather/badge_assignments", methods=["GET"])
@jwt_required()
def get_all_badge_assignments():
    try:
        all_assignments = []
        url = "/api/v2/gather/badge_assignments"

        while url:
            r = zendesk_request("GET", url)
            data = r.json()

            if "badge_assignments" in data:
                all_assignments.extend(data["badge_assignments"])
            else:
                break

            url = data.get("next_page")
            if url and url.startswith("https://"):  
                # cortar domínio para usar no zendesk_request
                url = url.replace("https://conecta.bcrcx.com", "")

        return jsonify({"badge_assignments": all_assignments}), 200

    except Exception as e:
        print(f"Erro ao buscar badge_assignments: {e}")
        return jsonify({"error": "Falha ao buscar badges"}), 502



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

    # Ajuste seguro do next_page para passar pelo proxy
    if result_json.get("next_page"):
        parsed = urlparse(result_json["next_page"])
        query_params = parse_qs(parsed.query)
        next_page_number = query_params.get("page", [page])[0]
        next_per_page = query_params.get("per_page", [per_page])[0]

        # Reconstruir URL do proxy apenas com page e per_page
        result_json["next_page"] = f"https://zendesk-proxy-na06.onrender.com/api/search/users?page={next_page_number}&per_page={next_per_page}"

    return jsonify(result_json), r.status_code




@app.route("/api/users/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):  # <- agora recebe direto do path
    r = zendesk_request("GET", f"/api/v2/users/{user_id}")
    return jsonify(r.json()), r.status_code


@app.route("/api/v2/users/<int:user_id>/organization_memberships.json", methods=["GET"])
@jwt_required()
def get_user_organization_memberships(user_id):
    """Proxy para GET /api/v2/users/{user_id}/organization_memberships.json no Zendesk."""
    r = zendesk_request("GET", f"/api/v2/users/{user_id}/organization_memberships.json")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@jwt_required()
def update_user(user_id):
    data = request.get_json()
    r = zendesk_request("PUT", f"/api/v2/users/{user_id}.json", json=data)
    return jsonify(r.json()), r.status_code


@app.route("/api/v2/organizations/<int:organization_id>/organization_memberships.json", methods=["GET"])
@jwt_required()
def get_organization_memberships(organization_id):
    """Proxy para GET /api/v2/organizations/{organization_id}/organization_memberships.json no Zendesk."""
    r = zendesk_request("GET", f"/api/v2/organizations/{organization_id}/organization_memberships.json")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


@app.route("/api/help_center/votes/<int:vote_id>", methods=["DELETE"])
@jwt_required()
def delete_vote(vote_id):
    r = zendesk_request("DELETE", f"/api/v2/help_center/votes/{vote_id}")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


@app.route("/api/community/posts/<int:post_id>/up", methods=["POST"])
@jwt_required()
def upvote_post(post_id):
    # Encaminha o payload recebido do frontend para a Zendesk
    data = request.get_json() or {}
    r = zendesk_request("POST", f"/api/v2/community/posts/{post_id}/up", json=data)
    # Algumas respostas podem não vir em JSON; retorna texto bruto quando necessário
    try:
        return jsonify(r.json()), r.status_code
    except Exception:
        return (r.text, r.status_code)

@app.route("/api/help_center/votes", methods=["GET", "OPTIONS"])
@jwt_required(optional=True)
def proxy_help_center_votes():
    # Preflight
    if request.method == "OPTIONS":
        resp = make_response(("", 200))
        origin = request.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    params = dict(request.args) if request.args else None
    r = zendesk_request("GET", "/api/v2/help_center/votes", params=params)
    resp = make_response((r.text, r.status_code))
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

@app.route("/api/community/posts", methods=["GET"])
@jwt_required()
def get_post():
    r = zendesk_request("GET", "/api/v2/community/posts")
    return jsonify(r.json()), r.status_code


@app.route("/api/gather/badges/<badge_id>", methods=["GET"])
@jwt_required()
def get_badge_by_id(badge_id):
    try:
        r = zendesk_request("GET", f"/api/v2/gather/badges/{badge_id}")
        return jsonify(r.json()), r.status_code
    except Exception as e:
        print(f"Erro ao buscar badge {badge_id}: {e}")
        return jsonify({"error": "Falha ao buscar badge"}), 502



@app.route("/api/user_fields/<int:field_id>", methods=["GET"])
@jwt_required()
def get_user_field(field_id):
    r = zendesk_request("GET", f"/api/v2/user_fields/{field_id}")
    return jsonify(r.json()), r.status_code

@app.route("/api/users/<int:user_id>/user_fields/<int:field_id>", methods=["GET"])
@jwt_required()
def get_user_field_value(user_id, field_id):
    """Retorna o valor de um campo customizado para um usuário específico."""
    field_def_r = zendesk_request("GET", f"/api/v2/user_fields/{field_id}")
    if field_def_r.status_code != 200:
        return jsonify({"error": "Campo não encontrado"}), field_def_r.status_code
    field_key = field_def_r.json().get("user_field", {}).get("key")
    if not field_key:
        return jsonify({"error": "Não foi possível obter o key do campo"}), 500

    user_r = zendesk_request("GET", f"/api/v2/users/{user_id}.json")
    if user_r.status_code != 200:
        return jsonify({"error": "Usuário não encontrado"}), user_r.status_code

    user_json = user_r.json()
    value = (user_json.get("user", {}).get("user_fields", {}) or {}).get(field_key)

    return jsonify({
        "field_id": field_id,
        "field_key": field_key,
        "value": value
    }), 200

@app.route("/api/users/<int:user_id>/user_fields/<int:field_id>", methods=["PUT", "PATCH"])
@jwt_required()
def update_user_field_value(user_id, field_id):
    """Atualiza o valor de um campo customizado de usuário. Payload: {"value": <novo_valor>}"""
    body = request.get_json() or {}
    new_value = body.get("value")
    if new_value is None:
        return jsonify({"error": "Campo 'value' é obrigatório"}), 400

    field_def_r = zendesk_request("GET", f"/api/v2/user_fields/{field_id}")
    if field_def_r.status_code != 200:
        return jsonify({"error": "Campo não encontrado"}), field_def_r.status_code
    field_key = field_def_r.json().get("user_field", {}).get("key")
    if not field_key:
        return jsonify({"error": "Não foi possível obter o key do campo"}), 500

    payload = {
        "user": {
            "user_fields": {
                field_key: new_value
            }
        }
    }

    r = zendesk_request("PUT", f"/api/v2/users/{user_id}.json", json=payload)
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


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


@app.route("/api/tickets", methods=["POST"])
@jwt_required()
def create_ticket():
    """
    Cria um ticket no Zendesk.
    Agora aceita payloads com ou sem a chave "ticket".
    """

    data = request.get_json() or {}

    # 🔹 Se o payload vier no formato {"ticket": {...}}, usa diretamente
    if "ticket" in data and isinstance(data["ticket"], dict):
        ticket_data = data["ticket"]
    else:
        ticket_data = data  # formato plano

    subject = ticket_data.get("subject")
    comment_body = None

    # aceita comment.body ou description
    if isinstance(ticket_data.get("comment"), dict):
        comment_body = ticket_data["comment"].get("body")
    if not comment_body:
        comment_body = ticket_data.get("description") or ticket_data.get("body")

    if not subject or not comment_body:
        return jsonify({
            "error": "Campos obrigatórios ausentes",
            "required": ["subject", "description"],
            "hint": "Envie 'subject' e 'description' (ou 'comment.body')"
        }), 400

    # Monta o payload do ticket
    ticket = {
        "subject": subject,
        "comment": {"body": comment_body}
    }

    # uploads (anexos)
    uploads = ticket_data.get("uploads")
    if uploads:
        ticket["comment"]["uploads"] = uploads

    # Campos opcionais
    simple_fields = [
        "assignee_id", "group_id", "priority", "type",
        "external_id", "due_at", "brand_id", "organization_id",
        "requester_id", "ticket_form_id"
    ]
    list_fields = ["tags", "collaborator_ids"]
    object_fields = ["requester"]
    custom_fields = ticket_data.get("custom_fields") or ticket_data.get("fields")

    for key in simple_fields:
        if key in ticket_data and ticket_data.get(key) is not None:
            ticket[key] = ticket_data.get(key)

    for key in list_fields:
        if key in ticket_data and isinstance(ticket_data.get(key), list):
            ticket[key] = ticket_data.get(key)

    for key in object_fields:
        if key in ticket_data and isinstance(ticket_data.get(key), dict):
            ticket[key] = ticket_data.get(key)

    if isinstance(custom_fields, list):
        ticket["custom_fields"] = custom_fields

    payload = {"ticket": ticket}

    r = zendesk_request("POST", "/api/v2/tickets.json", json=payload)

    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


@app.route("/api/v2/tickets/<int:ticket_id>", methods=["GET"])  # rota solicitada
@jwt_required()
def get_ticket_v2(ticket_id):
    r = zendesk_request("GET", f"/api/v2/tickets/{ticket_id}.json")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


@app.route("/api/v2/tickets/<int:ticket_id>", methods=["PUT", "PATCH"])
@jwt_required()
def update_ticket_v2(ticket_id):
    """Atualiza um ticket no Zendesk.

    Aceita payloads nos formatos:
    - {"ticket": { ...campos suportados pelo Zendesk... }}
    - { ...campos suportados... } (formato plano, será encapsulado em {"ticket": ...})

    Observações:
    - Mesmo quando a chamada ao proxy vier como PATCH, a requisição ao Zendesk será enviada via PUT,
      pois o endpoint de atualização de ticket utiliza PUT.
    """

    data = request.get_json() or {}
    if not data:
        return jsonify({"error": "Body JSON é obrigatório"}), 400

    payload = data if isinstance(data.get("ticket"), dict) else {"ticket": data}

    r = zendesk_request("PUT", f"/api/v2/tickets/{ticket_id}.json", json=payload)
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


@app.route("/api/custom_objects/<string:object_key>/records", methods=["GET"])
@jwt_required()
def get_custom_object_records(object_key):

    params = dict(request.args) if request.args else None
    r = zendesk_request("GET", f"/api/v2/custom_objects/{object_key}/records", params=params)
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code

@app.route("/api/custom_objects/<string:object_key>/records", methods=["POST"])
@jwt_required()
def create_custom_object_record(object_key):
    """Cria um record em um objeto customizado.
    Novo payload esperado pelo Zendesk:
    {
      "custom_object_record": {
        "custom_object_fields": { ... },
        "name": "..."
      }
    }
    """
    data = request.get_json() or {}
    record = data.get("custom_object_record")
    if not isinstance(record, dict):
        return jsonify({"error": "Payload deve conter 'custom_object_record' (objeto)"}), 400
    # Valida campos mínimos
    if "custom_object_fields" not in record or not isinstance(record.get("custom_object_fields"), dict):
        return jsonify({"error": "'custom_object_record.custom_object_fields' é obrigatório e deve ser objeto"}), 400
    if "name" not in record:
        return jsonify({"error": "'custom_object_record.name' é obrigatório"}), 400

    r = zendesk_request("POST", f"/api/v2/custom_objects/{object_key}/records", json=data)
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code

@app.route("/api/custom_objects/<string:object_key>/records/<string:record_id>", methods=["GET"])
@jwt_required()
def get_custom_object_record(object_key, record_id):
    r = zendesk_request("GET", f"/api/v2/custom_objects/{object_key}/records/{record_id}")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code

@app.route("/api/custom_objects/<string:object_key>/records/<string:record_id>", methods=["PUT"])
@jwt_required()
def update_custom_object_record(object_key, record_id):
    """Atualiza um record existente.
    Payload esperado (mesmo da criação):
    {
      "custom_object_record": {
        "custom_object_fields": { ... },
        "name": "..."
      }
    }
    Campos adicionais suportados pelo Zendesk podem ser passados dentro de custom_object_record.
    """
    data = request.get_json() or {}
    record = data.get("custom_object_record")
    if not isinstance(record, dict):
        return jsonify({"error": "Payload deve conter 'custom_object_record' (objeto)"}), 400
    if "custom_object_fields" in record and not isinstance(record.get("custom_object_fields"), dict):
        return jsonify({"error": "'custom_object_record.custom_object_fields' deve ser objeto"}), 400

    r = zendesk_request("PUT", f"/api/v2/custom_objects/{object_key}/records/{record_id}", json=data)
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code

@app.route("/api/custom_objects/<string:object_key>/records/<string:record_id>", methods=["DELETE"])
@jwt_required()
def delete_custom_object_record(object_key, record_id):
    r = zendesk_request("DELETE", f"/api/v2/custom_objects/{object_key}/records/{record_id}")
    return jsonify(r.json() if r.text else {"status": r.status_code}), r.status_code


# =========================
# Inicialização
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Render define PORT
    app.run(host="0.0.0.0", port=port)