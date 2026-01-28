from app import app, db  # Importe seu app e o objeto db
# Importe também seus modelos para que o SQLAlchemy os reconheça
from models import ProfessionalProfile, User 

with app.app_context():
    print("Criando tabelas no Neon...")
    db.create_all()
    print("Tabelas criadas com sucesso!")
