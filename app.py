import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import db, User, BlogPost, Category, Comment  # Comment eklendi
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf


app = Flask(__name__)
app.config['SECRET_KEY'] = 'fitkodlar_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fitkodlar.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload klasörü ve izin verilen uzantılar
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Mail konfigürasyonu
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kadirlupu00@gmail.com'
app.config['MAIL_PASSWORD'] = "fjva dlcb xalj cefe"
app.config['MAIL_DEFAULT_SENDER'] = 'kadirlupu00@gmail.com'

csrf = CSRFProtect(app)

# Upload klasörü yoksa oluştur
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.context_processor
def inject_user_info():
    return dict(session=session)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.before_request
def load_categories():
    g.categories = Category.query.order_by(Category.name).all()

# Veritabanı tablosu oluştur
with app.app_context():
    db.create_all()

# Admin kontrol dekoratörü
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get("username")
        if not username:
            flash("Lütfen giriş yapınız.", "warning")
            return redirect(url_for("login"))
        user = User.query.filter_by(username=username).first()
        if not user or not user.is_admin:
            flash("Bu sayfaya erişim yetkiniz yok.", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/posts")
def posts():
    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).all()
    return render_template("posts.html", posts=posts)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Bu kullanıcı adı veya e-posta zaten kayıtlı.", "warning")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Kayıt başarılı! Giriş yapabilirsiniz.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

from datetime import datetime, timedelta
import random

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user:
            # Hesap kilit kontrolü
            if user.account_locked_until and user.account_locked_until > datetime.utcnow():
                remaining = (user.account_locked_until - datetime.utcnow()).seconds // 60 + 1
                flash(f"Hesabınız {remaining} dakika boyunca kilitli. Lütfen daha sonra tekrar deneyin.", "danger")
                return redirect(url_for("login"))

            if check_password_hash(user.password, password):
                # Başarılı girişte deneme sayısını sıfırla ve kilidi kaldır
                user.failed_login_attempts = 0
                user.account_locked_until = None
                db.session.commit()

                if user.is_admin:
                    session["user_id"] = user.id
                    session["username"] = user.username
                    session["is_admin"] = user.is_admin
                    flash("Giriş başarılı!", "success")
                    return redirect(url_for("welcome"))
                else:
                    # 2FA kodu üret
                    code = str(random.randint(100000, 999999))
                    user.twofa_code = code
                    user.twofa_expiry = datetime.utcnow() + timedelta(minutes=5)
                    db.session.commit()

                    msg = Message("Giriş Doğrulama Kodunuz", recipients=[user.email])
                    msg.body = f"Giriş kodunuz: {code} (5 dakika içinde geçerlidir)"
                    mail.send(msg)

                    session["twofa_email"] = user.email
                    flash("Doğrulama kodu e-posta adresinize gönderildi.", "info")
                    return redirect(url_for("twofa_verify"))
            else:
                # Yanlış şifre durumunda deneme sayısını artır
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

                if user.failed_login_attempts >= 3:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=10)
                    flash("Çok fazla başarısız deneme. Hesabınız 10 dakika kilitlendi.", "danger")
                else:
                    attempts_left = 3 - user.failed_login_attempts
                    flash(f"Şifre hatalı! {attempts_left} deneme hakkınız kaldı.", "warning")

                db.session.commit()
                return redirect(url_for("login"))
        else:
            flash("E-posta veya şifre hatalı!", "danger")

    return render_template("login.html")



@app.route("/2fa", methods=["GET", "POST"])
def twofa_verify():
    email = session.get("twofa_email")
    if not email:
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()

    if request.method == "POST":
        code = request.form["code"]
        if user and user.twofa_code == code and datetime.utcnow() < user.twofa_expiry:
            # Başarılı giriş
            session["user_id"] = user.id
            session["username"] = user.username
            session["is_admin"] = user.is_admin
            session.pop("twofa_email", None)  # geçici oturum verisini temizle
            user.twofa_code = None
            user.twofa_expiry = None
            db.session.commit()
            flash("Giriş başarılı!", "success")
            return redirect(url_for("welcome"))
        else:
            flash("Kod geçersiz veya süresi dolmuş.", "danger")
    return render_template("twofa.html")


@app.route("/welcome")
def welcome():
    if "username" not in session:
        flash("Lütfen giriş yapınız.", "warning")
        return redirect(url_for("login"))
    return render_template("welcome.html", username=session["username"])


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)
            msg = Message("Şifre Sıfırlama Bağlantısı", recipients=[email])
            msg.body = f"Lütfen aşağıdaki bağlantıya tıklayarak şifrenizi sıfırlayın:\n{reset_url}"
            mail.send(msg)
            flash("Şifre sıfırlama bağlantısı e-posta adresinize gönderildi.", "info")
        else:
            flash("Bu e-posta adresi sistemde kayıtlı değil.", "danger")
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except SignatureExpired:
        flash("Bağlantının süresi dolmuş.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Geçersiz bağlantı.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Kullanıcı bulunamadı.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form["password"]
        if not new_password:
            flash("Yeni şifre boş olamaz.", "danger")
            return render_template("reset_password.html", token=token)

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Şifreniz başarıyla güncellendi.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        flash("Lütfen giriş yapın.", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["username"])

@app.route("/logout")
def logout():
    session.clear()
    flash("Başarıyla çıkış yaptınız.", "info")
    return redirect(url_for("home"))

# Admin Paneli
@app.route("/admin")
@admin_required
def admin_panel():
    return redirect(url_for("admin_posts"))

@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.all()
    return render_template("admin/users.html", users=users)

@app.route("/admin/users/toggle_admin/<int:user_id>")
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == session["username"]:
        flash("Kendi admin yetkinizi değiştiremezsiniz.", "danger")
        return redirect(url_for("admin_users"))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash("Kullanıcının admin yetkisi güncellendi.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/delete/<int:user_id>")
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == session["username"]:
        flash("Kendinizi silemezsiniz!", "danger")
        return redirect(url_for("admin_users"))
    db.session.delete(user)
    db.session.commit()
    flash("Kullanıcı başarıyla silindi.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/posts")
@admin_required
def admin_posts():
    posts = BlogPost.query.order_by(BlogPost.created_at.desc()).all()
    return render_template("admin/posts.html", posts=posts)

@app.route("/admin/posts/new", methods=["GET", "POST"])
@admin_required
def new_post():
    categories = Category.query.all()
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        category_id = request.form.get("category_id")
        user = User.query.filter_by(username=session["username"]).first()

        # Görsel dosyası al
        file = request.files.get("image")
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

        post = BlogPost(title=title, content=content, author=user, category_id=category_id, image_path=filename)
        db.session.add(post)
        db.session.commit()
        flash("Gönderi başarıyla oluşturuldu.", "success")
        return redirect(url_for("admin_posts"))

    return render_template("admin/new_post.html", categories=categories)

@app.route("/admin/posts/edit/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    categories = Category.query.all()

    if request.method == "POST":
        post.title = request.form["title"]
        post.content = request.form["content"]
        category_id = request.form.get("category_id")
        post.category_id = int(category_id) if category_id else None

        # Görsel dosyası kontrolü
        file = request.files.get("image")
        if file and allowed_file(file.filename):
            # Eski görsel varsa sil
            if post.image_path:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], post.image_path)
                if os.path.exists(old_path):
                    os.remove(old_path)
            # Yeni görsel kaydet
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            post.image_path = filename

        db.session.commit()
        flash("Gönderi başarıyla güncellendi.", "success")
        return redirect(url_for("admin_posts"))

    return render_template("admin/edit_post.html", post=post, categories=categories)

@app.route("/admin/posts/delete/<int:post_id>")
@admin_required
def delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    # Görsel varsa sil
    if post.image_path:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], post.image_path)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(post)
    db.session.commit()
    flash("Gönderi başarıyla silindi.", "success")
    return redirect(url_for("admin_posts"))

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        flash("Lütfen giriş yapınız.", "warning")
        return redirect(url_for("login"))
    
    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        flash("Kullanıcı bulunamadı.", "danger")
        return redirect(url_for("login"))
    
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email:
            user.email = email
        
        if password:
            user.password = generate_password_hash(password)
        
        db.session.commit()
        flash("Profil başarıyla güncellendi.", "success")
        return redirect(url_for("profile"))
    
    return render_template("profile.html", user=user)

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if "username" not in session:
        flash("Lütfen giriş yapın.", "warning")
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()

    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]

        if username != user.username:
            if User.query.filter_by(username=username).first():
                flash("Bu kullanıcı adı zaten alınmış.", "danger")
                return redirect(url_for("edit_profile"))
        
        user.username = username
        user.email = email

        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if current_password or new_password or confirm_password:
            if not current_password:
                flash("Mevcut şifrenizi girin.", "danger")
                return redirect(url_for("edit_profile"))

            if not check_password_hash(user.password, current_password):
                flash("Mevcut şifre yanlış.", "danger")
                return redirect(url_for("edit_profile"))

            if not new_password:
                flash("Yeni şifre boş olamaz.", "danger")
                return redirect(url_for("edit_profile"))

            if new_password != confirm_password:
                flash("Yeni şifreler eşleşmiyor.", "danger")
                return redirect(url_for("edit_profile"))

            user.password = generate_password_hash(new_password)
            flash("Şifreniz başarıyla güncellendi.", "success")

        db.session.commit()
        session["username"] = user.username

        flash("Profil bilgileri güncellendi.", "success")
        return redirect(url_for("profile"))

    return render_template("edit_profile.html", user=user)

@app.route("/admin/add_category", methods=["GET", "POST"])
@admin_required
def add_category():
    if request.method == "POST":
        category_name = request.form.get("name")
        if category_name:
            existing = Category.query.filter_by(name=category_name).first()
            if existing:
                flash("Bu kategori zaten var.", "warning")
            else:
                new_category = Category(name=category_name)
                db.session.add(new_category)
                db.session.commit()
                flash("Kategori başarıyla eklendi!", "success")
                return redirect(url_for("add_category"))
        else:
            flash("Kategori adı boş olamaz!", "danger")
    
    categories = Category.query.order_by(Category.name).all()
    return render_template("admin/add_category.html", categories=categories)


@app.route("/test-session")
def test_session():
    return f"is_admin: {session.get('is_admin')}, user_id: {session.get('user_id')}"

@app.route('/category/<int:category_id>')
def posts_by_category(category_id):
    category = Category.query.get_or_404(category_id)
    posts = BlogPost.query.filter_by(category_id=category.id).order_by(BlogPost.created_at.desc()).all()
    return render_template('posts_by_category.html', category=category, posts=posts)

@app.route('/admin/posts/category/<int:category_id>')
@admin_required
def admin_posts_by_category(category_id):
    category = Category.query.get_or_404(category_id)
    posts = BlogPost.query.filter_by(category_id=category.id).order_by(BlogPost.created_at.desc()).all()
    categories = Category.query.all()
    return render_template('admin/posts_by_category.html', posts=posts, category=category, categories=categories)

@app.route("/post/<int:post_id>")
def post_detail(post_id):
    post = BlogPost.query.get_or_404(post_id)
    prev_post = BlogPost.query.filter(BlogPost.id < post_id).order_by(BlogPost.id.desc()).first()
    next_post = BlogPost.query.filter(BlogPost.id > post_id).order_by(BlogPost.id.asc()).first()
    print("Session user_id:", session.get("user_id"))
    return render_template("post_detail.html", post=post, prev_post=prev_post, next_post=next_post)

@app.route("/admin/category/edit/<int:category_id>", methods=["GET", "POST"])
@admin_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    if request.method == "POST":
        new_name = request.form.get("name")
        if new_name:
            existing = Category.query.filter_by(name=new_name).first()
            if existing and existing.id != category.id:
                flash("Bu isimde başka bir kategori zaten var.", "danger")
            else:
                category.name = new_name
                db.session.commit()
                flash("Kategori başarıyla güncellendi.", "success")
                return redirect(url_for("add_category"))
        else:
            flash("Kategori adı boş olamaz.", "warning")
    return render_template("admin/edit_category.html", category=category)


@app.route("/admin/category/delete/<int:category_id>")
@admin_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    
    # Bu kategoriye ait gönderi varsa silinmesin
    related_posts = BlogPost.query.filter_by(category_id=category.id).first()
    if related_posts:
        flash("Bu kategoriye ait gönderi bulunduğu için silinemez.", "danger")
        return redirect(url_for("add_category"))
    
    db.session.delete(category)
    db.session.commit()
    flash("Kategori silindi.", "success")
    return redirect(url_for("add_category"))


@app.route("/post/<int:post_id>/comment", methods=["POST"])
def add_comment(post_id):
    if "user_id" not in session:
        flash("Yorum yapabilmek için giriş yapmalısınız.", "warning")
        return redirect(url_for("login"))
    
    content = request.form.get("comment")  # burada 'comment' olmalı
    if not content:
        flash("Yorum boş olamaz.", "danger")
        return redirect(url_for("post_detail", post_id=post_id))
    
    comment = Comment(content=content, post_id=post_id, user_id=session["user_id"])
    db.session.add(comment)
    db.session.commit()
    
    flash("Yorumunuz eklendi.", "success")
    return redirect(url_for("post_detail", post_id=post_id))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Admin kullanıcı yoksa oluştur
        if not User.query.filter_by(username="admin").first():
            admin_user = User(
                username="admin",
                email="admin@fitkodlar.com",
                password=generate_password_hash("admin123"),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin kullanıcı oluşturuldu.")
    app.run(debug=True)
