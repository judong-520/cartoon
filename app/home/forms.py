import wtforms
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, ValidationError, EqualTo, Regexp, Email


from app.models import User


# 前台会员注册
class RegisterForm(FlaskForm):

    name = wtforms.StringField(
        label="昵称",
        validators=[
            DataRequired("昵称不能为空")
        ],
        description="昵称",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "昵称",
        }
    )

    email = wtforms.StringField(
        label="邮箱",
        validators=[
            DataRequired("邮箱不能为空"),
            Email("邮箱格式不正确！")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "邮箱",
        }
    )

    phone = wtforms.StringField(
        label="手机号码",
        validators=[
            DataRequired("手机号码不能为空"),
            Regexp("^((13[0-9])|(14[5,7])|(15[0-3,5-9])|(17[0,3,5-8])|(18[0-9])|166|198|199|(147))\\d{8}$",
                   message="手机格式不正确")
        ],
        description="手机号码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "手机",
        }
    )

    pwd = wtforms.PasswordField(
        label="密码",
        validators=[
            DataRequired("密码不能为空")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "密码",
        }
    )

    repwd = wtforms.PasswordField(
        label="确认密码",
        validators=[
            DataRequired("确认密码不能为空"),
            EqualTo('pwd', message="两次密码不一致")
        ],
        description="确认密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "确认密码",
        }
    )

    submit = wtforms.SubmitField(
        '注册',
        render_kw={
            "class": "btn btn-lg btn-success btn-block",
        }
    )

    def validate_name(self, field):
        name = field.data
        user = User.query.filter_by(name=name).count()
        if user == 1:
            raise ValidationError("昵称已经存在")

    def validate_email(self, field):
        email = field.data
        user = User.query.filter_by(email=email).count()
        if user == 1:
            raise ValidationError("邮箱已经注册")

    def validate_phone(self, field):
        phone = field.data
        user = User.query.filter_by(phone=phone).count()
        if user == 1:
            raise ValidationError("手机号已经注册")


class LoginForm(FlaskForm):

    name = wtforms.StringField(
        label="账号",
        validators=[
            DataRequired("用户名不能为空")
        ],
        description="账号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "昵称",
        }
    )

    # email = wtforms.StringField(
    #     label="邮箱",
    #     validators=[
    #         DataRequired("邮箱不能为空"),
    #         Email("邮箱格式不正确！")
    #     ],
    #     description="邮箱",
    #     render_kw={
    #         "class": "form-control input-lg",
    #         "placeholder": "邮箱",
    #     }
    # )
    #
    # phone = wtforms.StringField(
    #     label="手机号码",
    #     validators=[
    #         DataRequired("手机号码不能为空"),
    #         Regexp("1[3458]\\d{9}", message="手机格式不正确")
    #     ],
    #     description="手机号码",
    #     render_kw={
    #         "class": "form-control input-lg",
    #         "placeholder": "手机",
    #     }
    # )

    pwd = wtforms.PasswordField(
        label="密码",
        validators=[
            DataRequired("密码不能为空")
        ],
        description="密码",
        render_kw={
            "id": "input_password",
            "class": "form-control input-lg",
            "placeholder": "密码",
        }
    )

    submit = wtforms.SubmitField(
        "登录",
        render_kw={
            "class":"btn btn-lg btn-success btn-block"
        }
    )

    def validate_name(self, field):
        name = field.data
        name_count = User.query.filter_by(name=name).count()
        if name_count == 0:
            raise ValidationError("用户不存在")


class UserForm(FlaskForm):

    name = wtforms.StringField(
        label="昵称",
        validators=[
            DataRequired("昵称不能为空")
        ],
        description="昵称",
        render_kw={
            "class": "form-control",
            "placeholder": "昵称",
            "type": "text",
        }
    )

    email = wtforms.StringField(
        label="邮箱",
        validators=[
            DataRequired("邮箱不能为空"),
            Email("邮箱格式不正确！")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control",
            "placeholder": "邮箱",
            "type": "email",
        }
    )

    phone = wtforms.StringField(
        label="手机号码",
        validators=[
            DataRequired("手机号码不能为空"),
            Regexp("^((13[0-9])|(14[5,7])|(15[0-3,5-9])|(17[0,3,5-8])|(18[0-9])|166|198|199|(147))\\d{8}$",
                   message="手机格式不正确")
        ],
        description="手机号码",
        render_kw={
            "class": "form-control",
            "placeholder": "手机",
            "type": "text",
        }
    )

    face = wtforms.FileField(
        label="头像",

        description="头像",
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

    submit = wtforms.SubmitField(
        "保存修改",
        render_kw={
            "class": "btn btn-success glyphicon glyphicon-saved"
        }
    )


class PwdForm(FlaskForm):

    old_pwd = wtforms.PasswordField(
        label="旧密码",
        validators=[
            DataRequired("旧密码不能为空")
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "旧密码",
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
            "placeholder": "新密码",
        }
    )

    submit = wtforms.SubmitField(
        "修改密码",
        render_kw={
            "class": "btn btn-success"
        }
    )


class CommentForm(FlaskForm):
    content = wtforms.TextAreaField(
        label="内容",
        validators=[
            DataRequired("请输入内容！"),
        ],
        description="内容",
        render_kw={
            "id": "input_content",
        }
    )
    submit = wtforms.SubmitField(
        '提交评论',
        render_kw={
            "class": "btn btn-success",
            "id": "btn-sub",
        }
    )
