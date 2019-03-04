import os
import datetime

from sqlalchemy import or_

from app.models import db, Role, Admin, Tag, Movie, Preview, User, Comment, MovieCol, OpLog, AdminLog, UserLog, Auth
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, redirect, url_for, \
    session, request, flash

from app.admin.forms import LoginForm, TagForm, MovieForm, PreviewForm, OplogForm, PasswordForm, AuthForm, RoleForm, \
    AdminForm
from utils.functions import admin_login_required, encrypt_filename


admin = Blueprint('admin', __name__)  # 定义蓝图


# 上下文处理器
@admin.context_processor
def tpl_extra():
    date = dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    return date


@admin.route("/create_db/")  # 调用蓝图
@admin_login_required
def create_db():
    """
    创建数据库
    """
    db.create_all()
    return '创建数据库成功'


@admin.route("/create_role/")
@admin_login_required
def create_role():
    """
    测试-添加角色
    """
    role = Role(
        name='超级管理员',
        auths='',
    )
    db.session.add(role)
    db.session.commit()
    return '创建超级管理员角色成功'


@admin.route("/create_admin/")
@admin_login_required
def create_admin():
    """
    测试-添加管理员(注意必须先创建角色，然后创建管理员)
    """
    admin = Admin(
        name='admin',
        pwd=generate_password_hash('123456'),
        is_super=0,
        role_id=1
    )
    db.session.add(admin)
    db.session.commit()
    return '创建超级管理员成功'


@admin.route("/")
@admin_login_required
def index():
    """
    后台主页
    """
    # admin = Admin.query.join(Role).filter(Role.id == Admin.role_id, Admin.id == session["admin_id"]).first()
    # auths = admin.role.auths
    # print('auths:', auths)
    # auths = list(map(int, auths.split(",")))
    # print('auths_map:', auths)
    # auth_list = Auth.query.all()
    # print('auths_list:', auth_list)
    # urls = [v.url for v in auth_list for val in auths if val == v.id]
    # print('urls:', urls)
    # rule = request.url_rule
    # print(rule)
    return render_template('admin/index.html')


@admin.route("/login/", methods=['GET', 'POST'])
def login():
    """
    后台登录界面
    """
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.verify_pwd(data['pwd']):
            flash('密码错误', 'err')
            return redirect(url_for('admin.login'))
        session['admin'] = data['account']
        session['admin_id'] = admin.id
        adminlog = AdminLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
        )
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for("admin.index"))
    return render_template('admin/login.html', form=form)


@admin.route("/logout/")
@admin_login_required
def logout():
    """
    后台退出界面
    """
    session.clear()
    return redirect(url_for('admin.login'))


@admin.route("/pwd/", methods=['GET', 'POST'])
@admin_login_required
def pwd():
    """
    修改密码界面
    """
    form = PasswordForm()
    data = form.data
    # print('表单验证之前：', data)
    if form.validate_on_submit():
        # print('表单验证之后：', data)
        old_pwd = data['old_pwd']
        new_pwd = data['new_pwd']
        if old_pwd == new_pwd:
            flash('旧密码与新密码一致', 'err')
            return redirect(url_for('admin.pwd'))
        admin_id = session['admin_id']
        admin = Admin.query.get(admin_id)
        admin.pwd = generate_password_hash(new_pwd)
        db.session.add(admin)
        db.session.commit()
        flash('密码修改成功', 'ok')
        return redirect((url_for('admin.login')))
    return render_template('admin/pwd.html', form=form)


@admin.route("/tag/add/", methods=['GET', 'POST'])
@admin_login_required
def tag_add():
    """
    添加标签
    """
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag(
            name=data['name']
        )
        db.session.add(tag)
        db.session.commit()
        flash('添加成功', 'ok')
        return redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


@admin.route("/tag/list/<int:page>/", methods=['GET', 'POST'])
@admin_login_required
def tag_list(page=None):
    """
    标签列表
    """
    if page is None:
        page = 1
    page_data = Tag.query.order_by(Tag.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        # print('tag_list:', request.form['table_search'])
        search = request.form['table_search']
        page_data = Tag.query.filter(Tag.name.like("%" + search + "%")).paginate(page=page, per_page=10)  # flask模糊查询
    return render_template('admin/tag_list.html', page_data=page_data)


@admin.route("/tag/del/<int:id>/", methods=['GET'])
@admin_login_required
def tag_del(id=None):
    """
    删除标签
    """
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash('删除成功', 'ok')
    return redirect(url_for('admin.tag_list', page=1))


@admin.route("/tag/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_required
def tag_edit(id=None):
    """
    编辑标签
    """
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag.name = data['name']
        db.session.add(tag)
        db.session.commit()
        flash('添加成功', 'ok')
        return redirect(url_for('admin.tag_list', page=1))
    return render_template('admin/tag_edit.html', form=form, tag=tag)


@admin.route("/movie/add/", methods=['GET', 'POST'])
@admin_login_required
def movie_add():
    """
    添加电影
    """
    form = MovieForm()
    form.tag_id.choices = [(tag.id, tag.name) for tag in Tag.query.all()]
    # print(form.validate_on_submit())
    if form.validate_on_submit():
        from manage import app
        if not os.path.exists(app.config["UP_DIR"]):  # 如果上传文件的目录不存在，那么创建目录，并且赋予可读可写的权限
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], 'rw')
        data = form.data

        file_url = secure_filename(form.url.data.filename)  # form.url.data.filename用于获取文件名secure_filename()重写修改文件名
        end_name = str(file_url).split(".")[-1]
        url = encrypt_filename(file_url)  # 重命名文件，保障每个文件名独一无二
        url = url + '.' + end_name
        form.url.data.save(app.config["UP_DIR"] + url)  # 将文件存贮在本地

        logo_url = secure_filename(form.logo.data.filename)  # form.url.data.filename获取文件名，secure_filename()对文件名修改重写
        logo = encrypt_filename(logo_url)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        movie = Movie(
            title=data["title"],
            url=url,
            info=data["info"],
            logo=logo,
            star=int(data["star"]),
            playnum=0,
            commentnum=0,
            tag_id=int(data["tag_id"]),
            area=data['area'],
            release_time=data["release_time"],
            length=data["length"],
            is_over=0,
            is_TV=1
        )
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功", "ok")
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html', form=form)


@admin.route("/movie/list/<int:page>", methods=['GET', 'POST'])
@admin_login_required
def movie_list(page=None):
    """
    电影列表
    """
    if page == None:
        page = 1
    page_data = Movie.query.join(Tag).filter(Tag.id == Movie.tag_id).order_by(Movie.addtime.desc()).paginate(page=page, per_page=12)  # 关联查询
    if request.method == 'POST':
        print(request.form['table_search'])
        search = request.form['table_search']
        page_data = Movie.query.filter(Movie.title.like('%' + search + '%')).paginate(page=page, per_page=12)
    return render_template('admin/movie_list.html', page_data=page_data)


@admin.route("/movie/del/<int:id>", methods=['GET'])
@admin_login_required
def movie_del(id):
    """
    删除电影
    """
    movie = Movie.query.get_or_404(id)
    db.session.delete(movie)
    db.session.commit()
    flash('删除成功', 'ok')
    return redirect(url_for('admin.movie_list', page=1))


@admin.route("/movie/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_required
def movie_edit(id):
    """
    编辑电影
    """
    form = MovieForm()
    form.tag_id.choices = [(tag.id, tag.name) for tag in Tag.query.all()]
    movie = Movie.query.get_or_404(int(id))
    form.url.validators = []  # 因为是编辑，所以首先必须是非空才需要验证
    # print("form.url.validators", form.url.validators)
    form.logo.validators = []
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    # print(form.validate_on_submit())
    # print('FORM_DATA:', form.data)
    if form.validate_on_submit():
        from manage import app
        data = form.data
        # print("表单验证通过后：",data)
        # 如果文件夹不存在，那么就创建一个文件夹
        if not os.path.exists(app.config["UP_DIR"]):  # 如果文件夹不存在
            os.makedirs(app.config["UP_DIR"])  # 新建对应的文件夹
            os.chmod(app.config["UP_DIR"], "rw")  # 给文件夹赋予读写的权限

        # 如果视频文件修改了，就进行替换
        if form.url.data.filename != "":
            file_url = secure_filename(form.url.data.filename)  # form.url.data.filename用于获取文件名secure_filename()重写修改文件名
            end_name = str(file_url).split(".")[-1]
            url = encrypt_filename(file_url)  # 重命名文件，保障每个文件名独一无二
            url = url + '.' + end_name
            movie.url = url
            form.url.data.save(app.config["UP_DIR"] + url)  # 将文件存贮在本地

        # 如果图片文件修改了，就进行替换
        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = encrypt_filename(file_logo)
            form.logo.data.save(app.config["UP_DIR"] + movie.logo)

        movie.title = data["title"]
        movie.info = data["info"]
        movie.star = data["star"]
        movie.tag_id = data["tag_id"]
        movie.length = data["length"]
        movie.area = data["area"]
        movie.release_time = data["release_time"]
        db.session.add(movie)
        db.session.commit()
        flash("编辑成功！", "ok")
        return redirect(url_for('admin.movie_list', page=1))
    return render_template('admin/movie_edit.html', form=form, movie=movie)


@admin.route("/preview/add/", methods=['GET', 'POST'])
@admin_login_required
def preview_add():
    """
    添加预告电影
    """
    form = PreviewForm()
    print(form.validate_on_submit())
    print(form.data)
    if form.validate_on_submit():
        from manage import app
        if not os.path.exists(app.config["UP_DIR"]):  # 如果上传文件的目录不存在，那么创建目录，并且赋予可读可写的权限
            os.makedirs(app.config["UP_DIR"])
            os.chmod(app.config["UP_DIR"], 'rw')

        data = form.data
        logo_url = secure_filename(form.logo.data.filename)  # form.url.data.filename获取文件名，secure_filename()对文件名修改重写
        logo = encrypt_filename(logo_url)
        form.logo.data.save(app.config["UP_DIR"] + logo)
        preview = Preview(
            title=data['title'],
            logo=logo,
        )
        db.session.add(preview)
        db.session.commit()
        flash('添加预告成功', 'ok')
        return redirect(url_for('admin.preview_add'))
    return render_template('admin/preview_add.html', form=form)


@admin.route("/preview/list/<int:page>", methods=['GET', 'POST'])
@admin_login_required
def preview_list(page=None):
    """
    预告电影列表
    """
    if page is None:
        page = 1
    page_data = Preview.query.order_by(Preview.addtime.desc()).paginate(page=page, per_page=5)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = Preview.query.filter(Preview.title.like('%' + search + '%')).paginate(page=page, per_page=5)
    return render_template("admin/preview_list.html", page_data=page_data)


@admin.route("/preview/del/<int:id>", methods=['GET'])
@admin_login_required
def preview_del(id=None):
    """
    删除电影
    """
    preview = Preview.query.get_or_404(id)
    db.session.delete(preview)
    db.session.commit()
    return redirect(url_for('admin.preview_list', page=1))


@admin.route("/preview/edit/<int:id>", methods=['GET', 'POST'])
@admin_login_required
def preview_edit(id=None):
    """
    预告电影列表
    """
    preview = Preview.query.get_or_404(id)
    form = PreviewForm()
    # print("表单提交之前：", form.data)
    # print('表单验证：', form.validate_on_submit())
    if form.validate_on_submit():
        from manage import app
        if not os.path.exists(app.config["UP_DIR"]):  # 如果文件夹不存在
            os.makedirs(app.config["UP_DIR"])  # 新建对应的文件夹
            os.chmod(app.config["UP_DIR"], "rw")  # 给文件夹赋予读写的权限

        file_logo = secure_filename(form.logo.data.filename)
        logo = encrypt_filename(file_logo)
        form.logo.data.save(app.config["UP_DIR"] + logo)

        data = form.data
        preview.title = data['title']
        preview.logo = logo
        db.session.add(preview)
        db.session.commit()
        return redirect(url_for('admin.preview_list', page=1))
    return render_template('admin/preview_edit.html', form=form, preview=preview)


@admin.route("/user/view/<int:id>/", methods=['GET'])
@admin_login_required
def user_view(id=None):
    """
    查看会员
    """
    user = User.query.get_or_404(int(id))
    return render_template('admin/user_view.html', user=user)


@admin.route("/user/del/<int:id>/", methods=['GET'])
@admin_login_required
def user_del(id=None):
    """
    删除会员
    """
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash('删除会员成功', 'ok')
    return redirect(url_for('admin.user_list', page=1))


@admin.route("/user/list/<int:page>/", methods=['GET', 'POST'])
@admin_login_required
def user_list(page=None):
    """
    会员列表
    """
    if page is None:
        page = 1
    page_data = User.query.order_by(User.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = User.query.filter(User.name.like('%' + search + '%')).paginate(page=page, per_page=10)
    return render_template('admin/user_list.html', page_data=page_data)


@admin.route("/comment/list/<int:page>/", methods=["GET", "POST"])
@admin_login_required
def comment_list(page=None):
    """
    评论列表
    """
    if page == None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(Comment.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        print(search)
        # 连表多个模糊查询
        page_data = Comment.query.join(Movie).join(User).filter(
            Movie.id == Comment.movie_id,
            User.id == Comment.user_id
        ).filter(
            or_(
                Comment.content.like('%' + search + '%'),
                Movie.title.like('%' + search + '%'),
                User.name.like('%' + search + '%'))
        ).paginate(page=page, per_page=10)
    return render_template('admin/comment_list.html', page_data=page_data)


@admin.route("/comment/del/<int:id>/", methods=["GET"])
@admin_login_required
def comment_del(id=None):
    """
    评论列表
    """
    comment = Comment.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    flash('删除成功', 'ok')
    return redirect(url_for('admin.comment_list', page=1))


@admin.route("/moviecol/list/<int:page>/", methods=['GET', 'POST'])
@admin_login_required
def moviecol_list(page=None):
    """
    电影收藏列表
    """
    if page == None:
        page = 1
    page_data = MovieCol.query.join(Movie).join(User).filter(
        Movie.id == MovieCol.movie_id,
        User.id == MovieCol.user_id
    ).order_by(MovieCol.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = MovieCol.query.join(Movie).join(User).filter(
            Movie.id == MovieCol.movie_id,
            User.id == MovieCol.user_id
        ).filter(
            or_(
                Movie.title.like('%' + search + '%'),
                User.name.like('%' + search + '%')
            )
        ).paginate(page=page, per_page=10)
    return render_template('admin/moviecol_list.html', page_data=page_data)


@admin.route("/moviecol/del/<int:id>/", methods=['GET'])
@admin_login_required
def moviecol_del(id=None):
    """
    删除电影收藏
    """
    moviecol = MovieCol.query.get_or_404(id)
    db.session.delete(moviecol)
    db.session.commit()
    flash('删除成功', 'ok')
    return redirect(url_for('admin.moviecol_list', page=1))


@admin.route("/oplog/add/", methods=['GET', 'POST'])
@admin_login_required
def oplog_add():
    """
    添加操作日志
    """
    form = OplogForm()
    data = form.data
    # print('表单验证之前：', data)
    if form.validate_on_submit():
        # print('表单验证之后：', data)
        # print('Session:', session)
        oplog = OpLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason=data['reason']
        )
        db.session.add(oplog)
        db.session.commit()
        flash('添加操作日志成功', 'ok')
        return redirect(url_for('admin.oplog_add'))
    return render_template('admin/oplog_add.html', form=form)


@admin.route("/oplog/list/<int:page>/", methods=['GET', 'POST'])
@admin_login_required
def oplog_list(page=None):
    """
    操作日志列表
    """
    if page == None:
        page = 1
    page_data = OpLog.query.join(Admin).filter(
        Admin.id == OpLog.admin_id
    ).order_by(OpLog.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = OpLog.query.join(Admin).filter(
            Admin.id == OpLog.admin_id
        ).filter(
            or_(
                Admin.name.like('%' + search + '%'),
                OpLog.reason.like('%' + search + '%')
            )
        ).paginate(page=page, per_page=10)
    return render_template('admin/oplog_list.html', page_data=page_data)


@admin.route("/adminloginlog/list/<int:page>/", methods=['GET', 'POST'])
def adminloginlog_list(page=None):
    """
    管理员登录日志列表
    """
    if page == None:
        page = 1
    page_data = AdminLog.query.join(Admin).filter(
        Admin.id == AdminLog.admin_id
    ).order_by(AdminLog.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = AdminLog.query.join(Admin).filter(
            Admin.id == AdminLog.admin_id
        ).filter(
            Admin.name.like('%' + search + '%')
        ).paginate(page=page, per_page=10)
    return render_template('admin/adminloginlog_list.html', page_data=page_data)


@admin.route("/userloginlog/list/<int:page>/", methods=['GET', 'POST'])
def userloginlog_list(page=None):
    """
    会员登录日志列表
    """
    if page == None:
        page = 1
    page_data = UserLog.query.join(User).filter(
        User.id == UserLog.user_id
    ).order_by(UserLog.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = UserLog.query.join(User).filter(
            User.id == UserLog.user_id
        ).filter(
            User.name.like('%' + search + '%')
        ).paginate(page=page, per_page=10)
    return render_template('admin/userloginlog_list.html', page_data=page_data)


@admin.route("/auth/add/", methods=['GET', 'POST'])
def auth_add():
    """
    添加权限
    """
    form = AuthForm()
    data = form.data
    if form.validate_on_submit():
        url = data['url']
        name = data['name']
        auth = Auth(
            name=name,
            url=url
        )
        db.session.add(auth)
        db.session.commit()
        flash('添加成功', 'ok')
        return redirect(url_for('admin.auth_add'))
    return render_template('admin/auth_add.html', form=form)


@admin.route("/auth/list/<int:page>/", methods=['GET', 'POST'])
def auth_list(page=None):
    """
    权限列表
    """
    if page == None:
        page = 1
    page_data = Auth.query.order_by(Auth.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = Auth.query.filter(Auth.name.like('%' + search + '%')).paginate(page=page, per_page=10)
    return render_template('admin/auth_list.html', page_data=page_data)


@admin.route("/auth/edit/<int:id>/", methods=['GET', 'POST'])
def auth_edit(id=None):
    """
    编辑权限
    """
    form = AuthForm()
    data = form.data
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        auth.url = data['url']
        auth.name = data['name']
        db.session.add(auth)
        db.session.commit()
        flash('修改成功', 'ok')
        return redirect(url_for('admin.auth_list', page=1))
    return render_template('admin/auth_edit.html', form=form, auth=auth)


@admin.route("/auth/del/<int:id>/", methods=['GET'])
def auth_del(id=None):
    """
    删除权限
    """
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash('删除成功', 'ok')
    return redirect(url_for('admin.auth_list', page=1))


@admin.route("/role/add/", methods=['GET', "POST"])
def role_add():
    """
    添加角色
    """
    form = RoleForm()
    data = form.data
    form.auth.choices = [(auth.id, auth.name) for auth in Auth.query.all()]
    if form.validate_on_submit():
        name = data['name']
        auths = ','.join(map(str, data['auth']))
        print('auths:', auths)
        role = Role(
            name=name,
            auths=auths
        )
        db.session.add(role)
        db.session.commit()
        flash('角色添加成功', 'ok')
        return redirect(url_for('admin.role_add'))
    return render_template('admin/role_add.html', form=form)


@admin.route("/role/list/<int:page>/", methods=['GET', 'POST'])
def role_list(page=None):
    """
    角色列表
    """
    if page == None:
        page = 1
    page_data = Role.query.order_by(Role.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = Role.query.filter(Role.name.like('%' + search + '%')).paginate(page=page, per_page=10)
    return render_template('admin/role_list.html', page_data=page_data)


@admin.route("/role/del/<int:id>/", methods=['GET'])
def role_del(id=None):
    """
    角色列表
    """
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash('删除成功', 'ok')
    return redirect(url_for('admin.role_list', page=1))


@admin.route("/role/edit/<int:id>/", methods=['GET', 'POST'])
def role_edit(id=None):
    """
    角色列表
    """
    role = Role.query.get_or_404(id)
    form = RoleForm()
    form.auth.choices = [(auth.id, auth.name) for auth in Auth.query.all()]
    if form.validate_on_submit():
        name = form.data['name']
        auths = ','.join(map(str, form.data['auth']))
        role.name = name
        role.auths = auths
        db.session.add(role)
        db.session.commit()
        flash('编辑成功', 'ok')
        return redirect(url_for('admin.role_list', page=1))
    return render_template('admin/role_edit.html', form=form, role=role)


@admin.route("/admin/add/", methods=['GET', 'POST'])
def admin_add():
    """
    添加管理员
    """
    form = AdminForm()
    form.role_id.choices = [(role.id, role.name) for role in Role.query.all()]
    data = form.data
    if form.validate_on_submit():
        name = data['name']
        pwd = data['pwd']
        repwd = data['repwd']
        role_id = data["role_id"]
        if pwd != repwd:
            flash('两次密码不一致', 'err')
            return redirect(url_for('admin.admin_add'))
        admin = Admin(
            name=name,
            pwd=generate_password_hash(pwd),
            role_id=role_id,
            is_super=1
        )
        db.session.add(admin)
        db.session.commit()
        flash('添加成功', 'ok')
        return redirect(url_for('admin.admin_add'))
    return render_template('admin/admin_add.html', form=form)


@admin.route("/admin/list/<int:page>/", methods=['GET', 'POST'])
def admin_list(page=None):
    """
    管理员列表
    """
    if page == None:
        page = 1
    page_data = Admin.query.join(Role).filter(
        Role.id == Admin.role_id
    ).order_by(Admin.addtime.desc()).paginate(page=page, per_page=10)
    if request.method == 'POST':
        search = request.form['table_search']
        page_data = Admin.query.join(Role).filter(
            Role.id == Admin.role_id
        ).filter(
            or_(
                Admin.name.like('%' + search + '%'),
                Role.name.like('%' + search + '%')
            )
        ).paginate(page=page, per_page=10)
    return render_template('admin/admin_list.html', page_data=page_data)

