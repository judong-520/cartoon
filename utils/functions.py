import os
import uuid
import functools
from datetime import datetime
from flask import redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

db = SQLAlchemy()


def init_ext(app):
    db.init_app(app=app)


def get_database_uri(DATABASE):
    host = DATABASE.get('host')
    db = DATABASE.get('db')
    driver = DATABASE.get('driver')
    port = DATABASE.get('port')
    user = DATABASE.get('user')
    password = DATABASE.get('password')
    name = DATABASE.get('name')

    return '{}+{}://{}:{}@{}:{}/{}'.format(db, driver,
                                           user, password,
                                           host,port,
                                           name)


# 后台页面登录装饰器
def admin_login_required(view_fun):
    @functools.wraps(view_fun)
    def inner(*args, **kwargs):
        if 'admin' in session:
            return view_fun(*args, **kwargs)
        else:
            return redirect(url_for('admin.login'))
    return inner


# 前台页面登录装饰器
def user_login_required(view_fun):
    @functools.wraps(view_fun)
    def inner(*args, **kwargs):
        if 'user' in session and 'user_id' in session:
            return view_fun(*args, **kwargs)
        else:
            return redirect(url_for('home.login'))
    return inner


# 重命名文件名称
def encrypt_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


# 访问权限控制装饰器
def admin_verify(view_fun):
    @functools.wraps(view_fun)
    def decorated_function(*args, **kwargs):
        from app.models import Admin, Role, Auth
        admin = Admin.query.join(
            Role
        ).filter(
            Role.id == Admin.role_id,
            Admin.id == session["admin_id"]
        ).first()
        auths = admin.role.auths
        auths = list(map(int, auths.split(",")))
        auth_list = Auth.query.all()
        urls = [v.url for v in auth_list for val in auths if val == v.id]
        rule = request.url_rule
        if str(rule) not in urls:
            os.abort(404)
        return view_fun(*args, **kwargs)
    return decorated_function
