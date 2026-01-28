# Normax Marketplace (MVP)

**Normax – Consultoria Alimentícia Especializada**

## Rodar localmente

```bash
cd normax_marketplace_full
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Mac/Linux:
# source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Acesse: http://127.0.0.1:5000

## Notas
- Banco SQLite é criado automaticamente: `marketplace.db`
- Profissionais têm campo de WhatsApp no perfil; o app gera link `wa.me`.
- Para produção, defina `SECRET_KEY` e `DATABASE_URL` no ambiente.
