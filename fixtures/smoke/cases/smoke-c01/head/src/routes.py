from auth import require_auth

app = make_app()


@app.get("/admin")
def admin():
    if not require_auth(request.key):
        return deny()
    return render_admin_panel()
