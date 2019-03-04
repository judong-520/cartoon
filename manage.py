from flask_script import Manager
from utils.app import create_app
from utils.config import Config

app = create_app(Config)
manage = Manager(app=app)

if __name__ == '__main__':
    manage.run()
