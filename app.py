import os
import json
import secrets
from datetime import datetime, timedelta

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)

# =========================================================
# BRANDING
# =========================================================
APP_NAME = "Normax - Consultoria Alimentícia Especializada"

# =========================================================
# APP CONFIG
# =========================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-normax-secret-key")

db_url = os.environ.get("DATABASE_URL", "sqlite:///marketplace.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# =========================================================
# ADMIN (SIMPLES)
# =========================================================
ADMIN_KEY = os.environ.get("ADMIN_KEY", "admin123")  # mude isso em produção

def admin_required():
    if not session.get("is_admin"):
        abort(403)

# =========================================================
# UPLOADS
# =========================================================
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024  # 4MB
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# =========================================================
# DB / LOGIN
# =========================================================
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "warning"

# =========================================================
# LISTAS
# =========================================================
SERVICES_LIST = [
    "Elaboração de Manuais (BPF/MBP)", "POPs", "Manual do Manipulador",
    "Responsabilidade Técnica (RT) Mensal", "RT por Visita", "RT Temporário",
    "Implantação APPCC/HACCP", "Auditoria Interna", "Treinamento",
    "Layout e Fluxo", "Rotulagem Nutricional", "Adequação Vigilância Sanitária"
]

SEGMENTS_LIST = [
    "Padaria/Confeitaria", "Açougue", "Supermercado", "Restaurante",
    "Fábrica/Indústria", "Laticínios", "Cozinha Industrial",
    "Dark Kitchen", "Food Truck", "Distribuidora"
]

PROFESSIONS_LIST = [
    "Engenheiro de Alimentos", "Veterinário", "Zootecnista",
    "Nutricionista", "Tecnólogo em Alimentos", "Químico"
]

DAYS_OF_WEEK = [
    "Segunda-feira", "Terça-feira", "Quarta-feira",
    "Quinta-feira", "Sexta-feira", "Sábado", "Domingo"
]

# =========================================================
# HELPERS
# =========================================================
def dump_json_list(items):
    cleaned = []
    for x in items or []:
        x = (x or "").strip()
        if x and x not in cleaned:
            cleaned.append(x)
    return json.dumps(cleaned, ensure_ascii=False)

def load_json_list(value):
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def allowed_file(filename: str) -> bool:
    if not filename:
        return False
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTENSIONS

def save_profile_pic(file_storage, user_id: int) -> str:
    if not file_storage or not getattr(file_storage, "filename", ""):
        return ""
    original = secure_filename(file_storage.filename)
    if not original or not allowed_file(original):
        return ""
    _, ext = os.path.splitext(original.lower())
    stored = f"user_{user_id}_{int(datetime.utcnow().timestamp())}{ext}"
    file_storage.save(os.path.join(UPLOAD_FOLDER, stored))
    return stored

def normalize_whatsapp(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    return "".join(c for c in raw if c.isdigit())

def whatsapp_link(raw: str) -> str:
    if not raw:
        return ""
    raw = raw.strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    digits = "".join(c for c in raw if c.isdigit())
    if not digits:
        return ""
    if len(digits) in (10, 11):
        digits = "55" + digits
    return f"https://wa.me/{digits}"

def require_type(user_type: str):
    if not current_user.is_authenticated:
        abort(401)
    if current_user.user_type != user_type:
        abort(403)

# =========================================================
# MODELS
# =========================================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # company / professional

    professional_profile = db.relationship("ProfessionalProfile", backref="user", uselist=False)

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)

class ProfessionalProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True, index=True)

    profession = db.Column(db.String(100))
    registry_number = db.Column(db.String(50))
    city = db.Column(db.String(100))
    state = db.Column(db.String(2))

    whatsapp = db.Column(db.String(40))
    bio = db.Column(db.Text)

    profile_pic = db.Column(db.String(255))
    is_verified = db.Column(db.Boolean, default=False)

    services_json = db.Column(db.Text, default="[]")
    segments_json = db.Column(db.Text, default="[]")

    availability_slots = db.relationship(
        "AvailabilitySlot", backref="profile",
        lazy=True, cascade="all, delete-orphan"
    )

    @property
    def services(self):
        return load_json_list(self.services_json)

    @property
    def segments(self):
        return load_json_list(self.segments_json)

    @property
    def profile_pic_url(self):
        return f"/static/uploads/{self.profile_pic}" if self.profile_pic else ""

    @property
    def whatsapp_url(self):
        return whatsapp_link(self.whatsapp or "")

class AvailabilitySlot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    profile_id = db.Column(db.Integer, db.ForeignKey("professional_profile.id"), nullable=False, index=True)
    day_of_week = db.Column(db.String(20), nullable=False)
    start_time = db.Column(db.String(5), nullable=False)
    end_time = db.Column(db.String(5), nullable=False)
    mode = db.Column(db.String(20), nullable=False)
    price = db.Column(db.String(50))

class Demand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    segment = db.Column(db.String(100))
    service_type = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(2))
    status = db.Column(db.String(20), default="Aberto")  # Aberto / Fechado
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read = db.Column(db.Boolean, default=False)

    sender = db.relationship("User", foreign_keys=[sender_id])
    recipient = db.relationship("User", foreign_keys=[recipient_id])

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    demand_id = db.Column(db.Integer, db.ForeignKey("demand.id"), nullable=False, index=True)
    professional_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)

    message = db.Column(db.Text)
    proposed_price = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    demand = db.relationship("Demand", backref=db.backref("applications", lazy=True, cascade="all, delete-orphan"))
    professional = db.relationship("User", foreign_keys=[professional_user_id])

# ✅ Convites (empresa / profissional)
class Invite(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    user_type = db.Column(db.String(20), nullable=False)  # company/professional

    max_uses = db.Column(db.Integer, default=1, nullable=False)
    used_count = db.Column(db.Integer, default=0, nullable=False)

    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    is_active = db.Column(db.Boolean, default=True)

def validate_invite(code: str, user_type: str) -> Invite:
    code = (code or "").strip()
    if not code:
        raise ValueError("Código de convite é obrigatório.")

    inv = Invite.query.filter_by(code=code, is_active=True).first()
    if not inv:
        raise ValueError("Convite inválido ou desativado.")

    if inv.user_type != user_type:
        raise ValueError("Este convite não é do tipo selecionado.")

    if inv.expires_at and datetime.utcnow() > inv.expires_at:
        raise ValueError("Este convite expirou.")

    if inv.used_count >= inv.max_uses:
        raise ValueError("Este convite já atingiu o limite de uso.")

    return inv

# =========================================================
# AUTH HOOKS
# =========================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.context_processor
def inject_globals():
    unread = 0
    if current_user.is_authenticated:
        unread = Message.query.filter_by(recipient_id=current_user.id, read=False).count()

    return {
        "APP_NAME": APP_NAME,
        "SERVICES_LIST": SERVICES_LIST,
        "SEGMENTS_LIST": SEGMENTS_LIST,
        "PROFESSIONS_LIST": PROFESSIONS_LIST,
        "DAYS_OF_WEEK": DAYS_OF_WEEK,
        "unread_messages": unread,
        "is_admin": bool(session.get("is_admin"))
    }

# =========================================================
# ROUTES
# =========================================================
@app.route("/")
def index():
    return render_template("index.html")

# -----------------------------
# ADMIN
# -----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        key = (request.form.get("admin_key") or "").strip()
        if key == ADMIN_KEY:
            session["is_admin"] = True
            flash("Admin autenticado.", "success")
            return redirect(url_for("admin_professionals"))
        flash("Chave admin inválida.", "danger")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    flash("Admin saiu.", "info")
    return redirect(url_for("index"))

@app.route("/admin/professionals")
def admin_professionals():
    admin_required()
    profs = ProfessionalProfile.query.join(User).order_by(User.name.asc()).all()
    return render_template("admin_professionals.html", profs=profs)

@app.route("/admin/toggle_verify/<int:profile_id>", methods=["POST"])
def admin_toggle_verify(profile_id):
    admin_required()
    profile = ProfessionalProfile.query.get_or_404(profile_id)
    profile.is_verified = not bool(profile.is_verified)
    db.session.commit()
    flash("Status de verificação atualizado.", "success")
    return redirect(url_for("admin_professionals"))

# ✅ Admin: convites
@app.route("/admin/invites", methods=["GET", "POST"])
def admin_invites():
    admin_required()

    if request.method == "POST":
        user_type = request.form.get("user_type")
        max_uses = int(request.form.get("max_uses") or "1")
        days_valid = int(request.form.get("days_valid") or "30")

        if user_type not in ("company", "professional"):
            flash("Tipo inválido.", "danger")
            return redirect(url_for("admin_invites"))

        code = secrets.token_urlsafe(8).replace("-", "").replace("_", "")
        expires_at = datetime.utcnow() + timedelta(days=days_valid)

        inv = Invite(
            code=code,
            user_type=user_type,
            max_uses=max_uses,
            used_count=0,
            expires_at=expires_at,
            is_active=True
        )
        db.session.add(inv)
        db.session.commit()
        flash(f"Convite criado: {code}", "success")
        return redirect(url_for("admin_invites"))

    invites = Invite.query.order_by(Invite.created_at.desc()).all()
    return render_template("admin_invites.html", invites=invites)

@app.route("/admin/invites/<int:invite_id>/toggle", methods=["POST"])
def admin_invite_toggle(invite_id):
    admin_required()
    inv = Invite.query.get_or_404(invite_id)
    inv.is_active = not bool(inv.is_active)
    db.session.commit()
    flash("Convite atualizado.", "success")
    return redirect(url_for("admin_invites"))

# -----------------------------
# AUTH
# -----------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        name = (request.form.get("name") or "").strip()
        password = request.form.get("password") or ""
        user_type = request.form.get("user_type") or ""
        invite_code = (request.form.get("invite_code") or "").strip()

        if not email or not name or not password or user_type not in ("company", "professional"):
            flash("Preencha todos os campos corretamente.", "danger")
            return redirect(url_for("register"))

        # ✅ Convite obrigatório
        try:
            inv = validate_invite(invite_code, user_type)
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email já cadastrado.", "danger")
            return redirect(url_for("register"))

        user = User(email=email, name=name, user_type=user_type)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        if user.user_type == "professional":
            profile = ProfessionalProfile(user_id=user.id, services_json="[]", segments_json="[]")
            db.session.add(profile)
            db.session.commit()

        # incrementa uso do convite
        inv.used_count += 1
        db.session.commit()

        login_user(user)
        flash("Conta criada com sucesso!", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Bem-vinda(o) de volta!", "success")
            return redirect(url_for("dashboard"))

        flash("Login ou senha inválidos.", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Você saiu da sua conta.", "info")
    return redirect(url_for("index"))

# -----------------------------
# DASHBOARDS
# -----------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.user_type == "company":
        demands = Demand.query.filter_by(user_id=current_user.id).order_by(Demand.created_at.desc()).all()
        return render_template("dashboard_company.html", demands=demands)

    profile = ProfessionalProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        profile = ProfessionalProfile(user_id=current_user.id, services_json="[]", segments_json="[]")
        db.session.add(profile)
        db.session.commit()

    slots = AvailabilitySlot.query.filter_by(profile_id=profile.id).order_by(AvailabilitySlot.id.desc()).all()
    return render_template("dashboard_professional.html", profile=profile, slots=slots)

@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    require_type("professional")

    profile = ProfessionalProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        profile = ProfessionalProfile(user_id=current_user.id, services_json="[]", segments_json="[]")
        db.session.add(profile)
        db.session.commit()

    profile.profession = (request.form.get("profession") or "").strip() or None
    profile.registry_number = (request.form.get("registry_number") or "").strip() or None
    profile.city = (request.form.get("city") or "").strip() or None
    profile.state = ((request.form.get("state") or "").strip().upper()[:2]) or None
    profile.whatsapp = normalize_whatsapp(request.form.get("whatsapp") or "") or None
    profile.bio = (request.form.get("bio") or "").strip() or None

    profile.services_json = dump_json_list(request.form.getlist("services"))
    profile.segments_json = dump_json_list(request.form.getlist("segments"))

    file = request.files.get("profile_pic")
    if file and file.filename:
        stored = save_profile_pic(file, current_user.id)
        if not stored:
            flash("Imagem não aceita. Use PNG/JPG/JPEG/WEBP (até 4MB).", "danger")
            return redirect(url_for("dashboard"))
        profile.profile_pic = stored
        flash("Foto atualizada com sucesso!", "success")

    db.session.commit()
    flash("Perfil salvo com sucesso!", "success")
    return redirect(url_for("dashboard"))

# -----------------------------
# DISPONIBILIDADE (AGENDA)
# -----------------------------
@app.route("/add_availability", methods=["POST"])
@login_required
def add_availability():
    require_type("professional")

    profile = ProfessionalProfile.query.filter_by(user_id=current_user.id).first()
    if not profile:
        flash("Crie seu perfil antes de adicionar horários.", "warning")
        return redirect(url_for("dashboard"))

    day_of_week = request.form.get("day_of_week") or ""
    start_time = request.form.get("start_time") or ""
    end_time = request.form.get("end_time") or ""
    mode = request.form.get("mode") or ""
    price = (request.form.get("price") or "").strip() or None

    if day_of_week not in DAYS_OF_WEEK:
        flash("Dia da semana inválido.", "danger")
        return redirect(url_for("dashboard"))

    if not start_time or not end_time or not mode:
        flash("Preencha dia, horário e modalidade.", "danger")
        return redirect(url_for("dashboard"))

    slot = AvailabilitySlot(
        profile_id=profile.id,
        day_of_week=day_of_week,
        start_time=start_time,
        end_time=end_time,
        mode=mode,
        price=price
    )
    db.session.add(slot)
    db.session.commit()
    flash("Horário adicionado!", "success")
    return redirect(url_for("dashboard"))

@app.route("/delete_availability/<int:slot_id>")
@login_required
def delete_availability(slot_id):
    require_type("professional")

    slot = AvailabilitySlot.query.get_or_404(slot_id)
    if slot.profile.user_id != current_user.id:
        abort(403)

    db.session.delete(slot)
    db.session.commit()
    flash("Horário removido.", "info")
    return redirect(url_for("dashboard"))

# -----------------------------
# DEMANDAS (EMPRESA)
# -----------------------------
@app.route("/create_demand", methods=["GET", "POST"])
@login_required
def create_demand():
    require_type("company")

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()

        if not title or not description:
            flash("Título e descrição são obrigatórios.", "danger")
            return redirect(url_for("create_demand"))

        demand = Demand(
            user_id=current_user.id,
            title=title,
            description=description,
            segment=request.form.get("segment") or None,
            service_type=request.form.get("service_type") or None,
            city=(request.form.get("city") or "").strip() or None,
            state=(request.form.get("state") or "").strip().upper()[:2] or None
        )
        db.session.add(demand)
        db.session.commit()
        flash("Demanda publicada!", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_demand.html")

@app.route("/demands/<int:demand_id>/close", methods=["POST"])
@login_required
def close_demand(demand_id):
    require_type("company")
    demand = Demand.query.get_or_404(demand_id)
    if demand.user_id != current_user.id:
        abort(403)

    demand.status = "Fechado"
    db.session.commit()
    flash("Demanda marcada como concluída.", "success")
    return redirect(url_for("dashboard"))

@app.route("/demands/<int:demand_id>/applications")
@login_required
def view_applications(demand_id):
    require_type("company")
    demand = Demand.query.get_or_404(demand_id)
    if demand.user_id != current_user.id:
        abort(403)

    apps = Application.query.filter_by(demand_id=demand.id).order_by(Application.created_at.desc()).all()
    return render_template("applications.html", demand=demand, applications=apps)

# -----------------------------
# DEMANDAS (PROFISSIONAL)
# -----------------------------
@app.route("/demands")
@login_required
def list_demands():
    require_type("professional")
    demands = Demand.query.filter(Demand.status != "Fechado").order_by(Demand.created_at.desc()).all()
    return render_template("demands.html", demands=demands)

@app.route("/demands/<int:demand_id>/apply", methods=["GET", "POST"])
@login_required
def apply_demand(demand_id):
    require_type("professional")
    demand = Demand.query.get_or_404(demand_id)

    if demand.status == "Fechado":
        flash("Essa demanda já foi concluída.", "warning")
        return redirect(url_for("list_demands"))

    existing = Application.query.filter_by(demand_id=demand.id, professional_user_id=current_user.id).first()
    if existing:
        flash("Você já se candidatou a essa demanda.", "info")
        return redirect(url_for("list_demands"))

    if request.method == "POST":
        message = (request.form.get("message") or "").strip()
        proposed_price = (request.form.get("proposed_price") or "").strip()

        row = Application(
            demand_id=demand.id,
            professional_user_id=current_user.id,
            message=message or None,
            proposed_price=proposed_price or None
        )
        db.session.add(row)
        db.session.commit()
        flash("Candidatura enviada!", "success")
        return redirect(url_for("list_demands"))

    return render_template("apply_demand.html", demand=demand)

# -----------------------------
# MENSAGENS
# -----------------------------
@app.route("/messages")
@login_required
def messages():
    msgs = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
    Message.query.filter_by(recipient_id=current_user.id, read=False).update({"read": True})
    db.session.commit()
    return render_template("messages.html", messages=msgs)

@app.route("/send_message/<int:recipient_id>", methods=["GET", "POST"])
@login_required
def send_message(recipient_id):
    recipient = User.query.get_or_404(recipient_id)

    if recipient.user_type == current_user.user_type:
        abort(403)

    if request.method == "POST":
        body = (request.form.get("body") or "").strip()
        if not body:
            flash("Escreva uma mensagem.", "warning")
            return redirect(url_for("send_message", recipient_id=recipient_id))

        msg = Message(sender_id=current_user.id, recipient_id=recipient.id, body=body)
        db.session.add(msg)
        db.session.commit()
        flash("Mensagem enviada com sucesso!", "success")
        return redirect(url_for("messages"))

    profile_id = None
    if recipient.user_type == "professional":
        prof = ProfessionalProfile.query.filter_by(user_id=recipient.id).first()
        if prof:
            profile_id = prof.id

    return render_template("send_message.html", recipient=recipient, profile_id=profile_id)

# -----------------------------
# BUSCA E PERFIL PÚBLICO
# -----------------------------
@app.route("/search_professionals")
def search_professionals():
    query = ProfessionalProfile.query.join(User).filter(User.user_type == "professional")

    city = (request.args.get("city") or "").strip()
    state = (request.args.get("state") or "").strip().upper()
    profession = (request.args.get("profession") or "").strip()
    service = (request.args.get("service") or "").strip()
    segment = (request.args.get("segment") or "").strip()
    verified = request.args.get("verified")

    if city:
        query = query.filter(ProfessionalProfile.city.ilike(f"%{city}%"))
    if state:
        query = query.filter(ProfessionalProfile.state == state[:2])
    if profession:
        query = query.filter(ProfessionalProfile.profession == profession)
    if service:
        query = query.filter(ProfessionalProfile.services_json.ilike(f'%"{service}"%'))
    if segment:
        query = query.filter(ProfessionalProfile.segments_json.ilike(f'%"{segment}"%'))
    if verified == "1":
        query = query.filter(ProfessionalProfile.is_verified.is_(True))

    professionals = query.order_by(ProfessionalProfile.id.desc()).all()
    return render_template("search.html", professionals=professionals, q=request.args)

@app.route("/professional/<int:profile_id>")
def professional_detail(profile_id):
    profile = ProfessionalProfile.query.get_or_404(profile_id)
    return render_template("professional.html", profile=profile)

# =========================================================
# MAIN
# =========================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
