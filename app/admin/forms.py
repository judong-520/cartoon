import wtforms
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, ValidationError, EqualTo
from app.models import Admin, Tag, Movie, Preview, Auth, Role


class LoginForm(FlaskForm):
    account = wtforms.StringField(
        label="账号",
        validators=[
            DataRequired("账号不能为空")   # validators是进行数据合法性判断
        ],
        description="账号",
        render_kw={
            "class": "form-control",
            "placeholder": "输入账号",   # render_kw 渲染生成html代码，通过该参数可以加上各种class属性。
        }
    )

    pwd = wtforms.PasswordField(
        label="密码",
        validators=[
            DataRequired("密码不能为空")
        ],
        description="密码",
        render_kw={
            "class": "form-control",
            "placeholder": "输入密码",
        }
    )

    submit = wtforms.SubmitField(
        '登录',
        render_kw={
            "class": "btn btn-primary btn-block btn-flat",
        }
    )

    def validate_account(self, field):   # field就是输入账户的整个<input>标签
        account = field.data  # field.data即是<input>标签内，文本框输入的内容
        admin = Admin.query.filter_by(name=account).count()
        if admin == 0:
            raise ValidationError("无此用户")  # 验证失败，通过ValidationError引发抛出错误


class PasswordForm(FlaskForm):
    old_pwd = wtforms.PasswordField(
        label="旧密码",
        validators=[
            DataRequired("旧密码不能为空")
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "输入旧密码",
        }
    )
    new_pwd = wtforms.PasswordField(
        label="新密码",
        validators=[
            DataRequired("新密码不能为空")
        ],
        description="新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "输入新密码",
        }
    )
    submit = wtforms.SubmitField(
        '修改',
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_old_pwd(self, field):
        from flask import session
        old_pwd = field.data
        admin_id = session['admin_id']
        admin = Admin.query.get(admin_id)
        if not admin.verify_pwd(old_pwd):
            raise ValidationError('旧密码错误')


class TagForm(FlaskForm):
    name = wtforms.StringField(
        label='标签',
        validators=[
            DataRequired("标签不能为空")
        ],
        description='标签',
        render_kw={
            "class": "form-control",
            "id":"input_name",
            "placeholder": "输入标签名称",
        }
    )

    submit = wtforms.SubmitField(
        '确认',
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_name(self, field):
        name = field.data
        name_count = Tag.query.filter_by(name=name).count()
        if name_count != 0:
            raise ValidationError('该标签已经存在')


class MovieForm(FlaskForm):

    title = wtforms.StringField(
        label="片名",
        validators=[
            DataRequired("片名不能为空")  # validators是进行数据合法性判断
        ],
        description="片名",
        render_kw={
            "id":"input_title",
            "class": "form-control",
            "placeholder": "输入片名",  # render_kw 渲染生成html代码，通过该参数可以加上各种class属性。
        }
    )

    url = wtforms.StringField(
        label="文件",
        validators=[
            DataRequired("文件不能为空")
        ],
        description="文件",
        render_kw={
            "id": "input_url",
            "type": "file",
        }
    )

    info = wtforms.TextAreaField(
        label='简介',
        validators=[
            DataRequired("简介不能为空")
        ],
        description='简介',
        render_kw={
            "rows": 10,
            "class": "form-control",
            "id": "input_info",
        }
    )

    logo = wtforms.FileField(
        label='封面',
        validators=[
            DataRequired("封面不能为空")
        ],
        description='封面',
        render_kw={
            "id": "input_logo",
        }
    )

    star = wtforms.SelectField(
        label='星级',
        validators=[
            DataRequired("选择星级")
        ],
        coerce=int,
        choices=[(1, "1星"), (2, "2星"), (3, "3星"), (4, "4星"), (5, "5星")],
        description='星级',
        render_kw={
            "id": "input_star",
            "class": "form-control",
        }
    )

    tag_id = wtforms.SelectField(
        label='标签',
        validators=[
            DataRequired("选择标签")
        ],
        coerce=int,
        choices='',
        description='标签',
        render_kw={
            "id": "input_tag_id",
            "class": "form-control",
        }
    )

    area = wtforms.StringField(
        label="上映地区",
        validators=[
            DataRequired("上映地区不能为空")
        ],
        description="地区",
        render_kw={
            "id": "input_area",
            "class": "form-control",
            "placeholder": "输入上映地区",
        }
    )

    length = wtforms.StringField(
        label="片长",
        validators=[
            DataRequired("片长不能为空")
        ],
        description="片长",
        render_kw={
            "id": "input_length",
            "class": "form-control",
            "placeholder": "输入片长",
        }
    )

    release_time = wtforms.StringField(
        label="上映时间",
        validators=[
            DataRequired("上映时间不能为空")
        ],
        description="片长",
        render_kw={
            "type": "text",
            "id": "input_release_time",
            "class": "form-control",
            "placeholder": "输入上映时间",
        }
    )

    submit = wtforms.SubmitField(
        '确认',
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_title(self, field):
        title = field.data
        title_count = Movie.query.filter_by(title=title).count()
        if title_count != 0:
            raise ValidationError("片名已经存在")


# 添加预告
class PreviewForm(FlaskForm):

    title = wtforms.StringField(
        label="预告标题",
        validators=[
            DataRequired("预告标题不能为空")
        ],
        description="预告标题",
        render_kw={
            "class": "form-control input-lg",
            "id": "input_title",
            "placeholder": "输入预告标题"
        }
    )

    logo = wtforms.FileField(
        label="预告封面",
        validators=[
            DataRequired("预告封面不能为空")
        ],
        description="预告封面",
    )

    submit = wtforms.SubmitField(
        '确认',
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_title(self, field):
        title = field.data
        title_count = Preview.query.filter_by(title=title).count()
        if title_count != 0:
            raise ValidationError("预告标题已经存在")


class OplogForm(FlaskForm):
    reason = wtforms.StringField(
        label='操作原因',
        validators=[
            DataRequired("操作原因不能为空")
        ],
        description='操作原因',
        render_kw={
            "class": "form-control",
            "placeholder": "操作原因",
        }
    )

    submit = wtforms.SubmitField(
        '确认',
        render_kw={
            "class": "btn btn-primary",
        }
    )


class AuthForm(FlaskForm):
    # name = db.Column(db.String(100), unique=True)  # 权限名称
    # url = db.Column(db.String(255), unique=True)  # 权限地址
    name = wtforms.StringField(
        label='权限名称',
        validators=[
            DataRequired("权限名称不能为空")
        ],
        description='权限',
        render_kw={
            "class": "form-control",
            "placeholder": "输入权限名称",
        }
    )

    url = wtforms.StringField(
        label='权限地址',
        validators=[
            DataRequired("权限地址名称不能为空")
        ],
        description='权限地址',
        render_kw={
            "class": "form-control",
            "placeholder": "输入权限地址",
        }
    )
    submit = wtforms.SubmitField(
        '确认',
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_name(self, field):
        name = field.data
        name_count = Auth.query.filter_by(name=name).count()
        if name_count != 0:
            raise ValidationError('权限名称已存在')

    def validate_url(self, field):
        url = field.data
        url_count = Auth.query.filter_by(url=url).count()
        if url_count != 0:
            raise ValidationError('权限地址已存在')


class RoleForm(FlaskForm):
    # name = db.Column(db.String(100), unique=True)  # 名称
    # auths = db.Column(db.String(600))  # 权限列表
    name = wtforms.StringField(
        label='角色名称',
        validators=[
            DataRequired("角色名称不能为空")
        ],
        description='角色',
        render_kw={
            "class": "form-control",
            "placeholder": "输入角色名称",
        }
    )
    auth = wtforms.SelectMultipleField(
        label='权限名称',
        validators=[
            DataRequired("权限名称不能为空")
        ],
        coerce=int,
        choices='',
        description='权限',
        render_kw={
            "class": "form-control",
            "id": "input_url",
            "placeholder": "选择角色",
            "type": "checkbox",
        }
    )
    submit = wtforms.SubmitField(
        '确认',
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_name(self, field):
        name = field.data
        name_count = Role.query.filter_by(name=name).count()
        if name_count != 0:
            raise ValidationError('角色已存在')


class AdminForm(FlaskForm):
    name = wtforms.StringField(
        label="管理员名称",
        validators=[
            DataRequired("管理员名称不能为空")
        ],
        description="管理员名称",
        render_kw={
            "class": "form-control",
            "placeholder": "输入管理员名称",
        }
    )

    pwd = wtforms.PasswordField(
        label="管理员密码",
        validators=[
            DataRequired("管理员密码不能为空")
        ],
        description="管理员密码",
        render_kw={
            "class": "form-control",
            "placeholder": "输入管理员密码",
        }
    )
    repwd = wtforms.PasswordField(
        label="重复管理员密码",
        validators=[
            DataRequired("管理员重复密码不能为空"),
        ],
        description="重复管理员密码",
        render_kw={
            "class": "form-control",
            "placeholder": "重复输入管理员密码",
        }
    )
    role_id = wtforms.SelectField(
        label="所属角色",
        validators=[
            DataRequired("选择所属角色")
        ],
        coerce=int,
        # 采用下拉选择的方式进行所属角色的选择
        choices='',
        description="所属角色",
        render_kw={
            "class": "form-control",
        }
    )

    submit = wtforms.SubmitField(
        '确认',
        render_kw={
            "class": "btn btn-primary",
        }
    )

    def validate_name(self, field):
        name = field.data
        name_count = Admin.query.filter_by(name=name).count()
        if name_count != 0:
            raise ValidationError('该管理员名称已存在')
