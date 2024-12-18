# from app import app


#############
from app import create_app

app = create_app(config_name='DevelopmentConfig')  # For development


#########

if __name__ == '__main__':
    app.run(debug=True)
