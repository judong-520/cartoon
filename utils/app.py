import os
from flask import Flask, render_template

from utils.settings import TEMPLATE_DIR, STATIC_DIR
from utils.functions import init_ext
from app.home.views import home as home_blueprint
from app.admin.views import admin as admin_blueprint


def create_app(config):

    app = Flask(__name__,
                template_folder=TEMPLATE_DIR,
                static_folder=STATIC_DIR)
    app.secret_key = '123456'  # 或者 app.config["SECRET_KEY"] = "123456"
    # 文件上传的保存路径配置
    app.config["UP_DIR"] = os.path.join(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                        'static/uploads/')
    app.config["US_DIR"] = os.path.join(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                        'static/uploads/users/')
    app.config["REDIS_URL"] = "redis://47.98.173.29:6379"

    @app.errorhandler(404)
    def page_not_found(error):
        """
        搭建404 “page not found”页面
        """
        return render_template('home/404.html'), 404

    app.register_blueprint(blueprint=home_blueprint)
    app.register_blueprint(blueprint=admin_blueprint, url_prefix='/admin')
    app.config.from_object(config)
    init_ext(app)
    return app

