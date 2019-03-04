import os
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, session, request, jsonify
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from app.home.forms import RegisterForm, LoginForm, UserForm, PwdForm, CommentForm
from app.models import User, db, UserLog, Comment, Movie, MovieCol, Tag
from utils.functions import user_login_required, encrypt_filename

home = Blueprint('home', __name__)  # 定义蓝图


@home.route('/')
def _home():
    return redirect(url_for('home.index', page=1))


@home.route("/<int:page>/", methods=['GET', 'POST'])  # 调用蓝图pip
def index(page=None):
    """
    返回主页面
    """
    tags = Tag.query.all()
    page_data = Movie.query
    type = request.args.get('type', 0)
    if int(type) != 0:
        page_data = page_data.filter_by(tag_id=int(type))
    star = request.args.get('star', 0)
    if int(star) != 0:
        page_data = page_data.filter_by(star=int(star))
    year = request.args.get('year', 0)
    if int(year) != 0:
        if int(year) == 1:
            page_data = page_data.order_by(Movie.release_time.desc())
        elif int(year) == 2:
            page_data = page_data.order_by(Movie.release_time.asc())
        else:
            page_data = page_data.filter(Movie.release_time.like(year + '%'))
    pn = request.args.get('pn', 0)
    if int(pn) != 0:
        if int(pn) == 1:  # 1代表播放数量从高到低排序
            page_data = page_data.order_by(Movie.playnum.desc())
        else:
            page_data = page_data.order_by(Movie.playnum.asc())
    cn = request.args.get('cn', 0)
    if int(cn) != 0:
        if int(cn) == 1:  # 1代表播放数量从高到低排序, 2代表从低到高排序
            page_data = page_data.order_by(Movie.commentnum.desc())
        else:
            page_data = page_data.order_by(Movie.commentnum.asc())
    if page == None:
        page = 1
    page_data = page_data.paginate(page=page, per_page=12)
    data = dict(
        tags=tags,
        type=type,
        star=star,
        year=year,
        pn=pn,
        cn=cn
    )
    new_movie = Movie.query.order_by(Movie.addtime.desc()).paginate(page=page, per_page=10)
    Japan_movie = Movie.query.filter(Movie.area.ilike('%' + '日本' + '%')).paginate(page=page, per_page=10)
    China_movie = Movie.query.filter(Movie.area.ilike('%' + '中国' + '%')).paginate(page=page, per_page=10)
    movie_over = Movie.query.filter(Movie.is_over == 1).order_by(Movie.addtime.desc()).paginate(page=page, per_page=8)
    return render_template('home/index.html',
                           data=data,
                           page_data=page_data,
                           new_movie=new_movie,
                           Japan_movie=Japan_movie,
                           China_movie=China_movie,
                           movie_over=movie_over)


@home.route("/login/", methods=['GET', 'POST'])
def login():
    """
    登录页面
    """
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        account = data['name']
        pwd = data['pwd']
        user = User.query.filter_by(name=account).first()
        if not user.verify_pwd(pwd):
            flash("密码错误", "err")
            return redirect(url_for("home.login"))
        session['user'] = user.name
        session['user_id'] = user.id
        userlog = UserLog(
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(url_for('home.index', page=1))
    return render_template('home/login.html', form=form)


@home.route("/logout/")
def logout():
    """
    退出页面
    """
    session.clear()
    return redirect(url_for('home.login'))


@home.route("/register/", methods=['GET', 'POST'])
def register():
    """
    注册页面
    """
    form = RegisterForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            uuid=uuid.uuid4().hex,
            pwd=generate_password_hash(data['pwd']),
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('home.login'))
    return render_template('home/register.html', form=form)


@home.route("/user/", methods=['GET', 'POST'])
@user_login_required
def user():
    """
    会员页面
    """
    # user = session['user']
    user = User.query.get(session['user_id'])
    form = UserForm()

    if form.validate_on_submit():
        data = form.data
        if data['face']:
            from manage import app
            if not os.path.exists(app.config["US_DIR"]):  # 文件夹不存在则新建文件夹
                os.makedirs(app.config["US_DIR"])
                os.chmod(app.config["US_DIR"], 'rw')
            file_name = secure_filename(data['face'].filename)  # secure_filename避免上传文件名有中文的麻烦
            user.face = encrypt_filename(file_name)
            form.face.data.save(app.config["US_DIR"] + user.face)

        name_count = User.query.filter_by(name=data["name"]).count()
        if data["name"] != user.name and name_count == 1:
            flash("昵称已存在", "err")
            return redirect(url_for("home.user"))

        email_count = User.query.filter_by(email=data["email"]).count()
        if data["email"] != user.email and email_count == 1:
            flash("邮箱已经存在", "err")
            return redirect(url_for("home.user"))

        phone_count = User.query.filter_by(phone=data["phone"]).count()
        if data["phone"] != user.phone and phone_count == 1:
            flash("手机已经存在", "err")
            return redirect(url_for("home.user"))

        user.name = data["name"]
        user.email = data["email"]
        user.phone = data["phone"]
        user.info = data["info"]
        db.session.add(user)
        db.session.commit()
        flash("修改成功", "ok")
        return redirect(url_for("home.user"))

    return render_template('home/user.html', form=form, user=user)


@home.route("/pwd/", methods=['GET', 'POST'])
@user_login_required
def pwd():
    """
    修改密码页面
    """
    form = PwdForm()
    data = form.data
    if form.validate_on_submit():
        user = User.query.filter_by(id=session['user_id']).first()
        if not user.verify_pwd(data['old_pwd']):
            flash('旧密码错误', 'err')
            return redirect(url_for('home.pwd'))
        if data['old_pwd'] == data['new_pwd']:
            flash('旧密码与新密码一致', 'err')
            return redirect(url_for('home.pwd'))
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash('密码修改成功，请重新登录', 'ok')
        return redirect(url_for('home.logout'))
    return render_template('home/pwd.html', form=form)


@home.route("/comments/<int:page>/", methods=['GET'])
@user_login_required
def comments(page=None):
    """
    评论页面
    """
    if page == None:
        page=1
    page_data = Comment.query.join(User).join(Movie).filter(
        User.id == session['user_id'],
        Movie.id == Comment.movie_id
    ).order_by(Comment.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('home/comments.html', page_data=page_data)


@home.route("/comment/del/<int:id>/", methods=['GET'])
@user_login_required
def comment_del(id=None):
    """
    删除评论
    """
    content = Comment.query.get_or_404(id)
    db.session.delete(content)
    db.session.commit()
    flash('删除评论成功', 'ok')
    return redirect(url_for('home.comments', page=1))


@home.route("/loginlog/<int:page>/", methods=['GET'])
@user_login_required
def loginlog(page=None):
    """
    登录日志页面
    """
    if page == None:
        page = 1
    page_data = UserLog.query.order_by(UserLog.addtime.desc()).paginate(page=page, per_page=20)
    return render_template('home/loginlog.html', page_data=page_data)


@home.route("/moviecol/<int:page>/", methods=['GET'])
@user_login_required
def moviecol(page=None):
    """
    电影收藏页面
    """
    if page == None:
        page = 1
    page_data = MovieCol.query.join(Movie).join(User).filter(
        Movie.id == MovieCol.movie_id,
        User.id == session['user_id']
    ).order_by(MovieCol.addtime.desc()).paginate(page=page, per_page=10)
    return render_template('home/moviecol.html', page_data=page_data)


@home.route("/search/<int:page>")
def search(page=None):
    """
    电影搜索页面
    """
    if page is None:
        page = 1
    key = request.args.get('key', '')
    page_data = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).order_by(Movie.addtime.desc()).paginate(page=page, per_page=10)
    num = Movie.query.filter(Movie.title.ilike('%' + key + '%')).count()
    return render_template('home/search.html', key=key, page_data=page_data, num=num)


@home.route("/play/<int:id>/<int:page>/", methods=['GET', 'POST'])
def play(id=None, page=None):
    """
    播放页面
    """
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()

    movie.playnum = movie.playnum + 1
    db.session.add(movie)
    db.session.commit()

    if page is None:
        page = 1
        # 查询的时候关联标签，采用join来加进去,多表关联用filter,过滤用filter_by
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=15)

    form = CommentForm()
    if 'user' in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['content'],
            movie_id=id,
            user_id=session['user_id']
        )
        db.session.add(comment)
        db.session.commit()
        movie.commentnum = movie.commentnum + 1
        db.session.add(movie)
        db.session.commit()
        return redirect(url_for("home.play", id=movie.id, page=1))
    return render_template('home/play.html', movie=movie, page_data=page_data, form=form)


@home.route("/moviecol/add/", methods=['GET'])
@user_login_required
def moviecol_add():
    """
    添加电影收藏
    """
    movie_id = request.args.get('movie_id', 0)
    user_id = request.args.get('user_id', 0)
    moviecol_count = MovieCol.query.join(User).join(Movie).filter(
        Movie.id == int(movie_id),
        User.id == int(user_id)
    ).count()
    if moviecol_count != 0:
        data = {'code': 300, 'msg': '你已收藏'}
    else:
        moviecol = MovieCol(
            user_id=int(user_id),
            movie_id=int(movie_id)
        )
        db.session.add(moviecol)
        db.session.commit()
        data = {'code': 200, 'msg': '收藏成功'}
    return jsonify(data)
